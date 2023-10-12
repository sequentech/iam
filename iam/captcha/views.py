# This file is part of iam.
# Copyright (C) 2014-2020  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

import os
import json
import random
import string
from django.views.generic import View
from django.conf import settings
from django.db import transaction

from celery import shared_task

try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter
except ImportError:
    import Image
    import ImageDraw
    import ImageFont
    import ImageFilter

from .models import Captcha
from utils import json_response


def newcaptcha():
    letters = string.ascii_uppercase + string.digits
    code = ''.join(random.choice(letters) for _ in range(10))
    challenge = ''.join(random.choice(letters) for _ in range(4))
    make_image(challenge, code)
    fname = code + '.png'
    path = '/static/captcha/%s' % fname
    c = Captcha(code=code, challenge=challenge, path=path)
    c.save()
    return c


@shared_task(name="captcha.io.generate_captcha")
def generate_captcha(amount=1):
    from captcha.views import newcaptcha
    repeat = 0
    while repeat < amount:
        newcaptcha()
        repeat += 1


class NewCaptcha(View):
    def get(self, request):
        # TODO: write down ip and put in blacklist if order a lot captchas
        generate_captcha()

        with transaction.atomic():
            captcha = Captcha.objects.select_for_update().filter(used=False).first()
            captcha.used = True
            captcha.save()
        data = {
            'captcha_code': captcha.code,
            'image_url': captcha.path
        }
        return json_response(data)
new_captcha = NewCaptcha.as_view()


def getsize(font, text):
    if hasattr(font, 'getbbox'):
        left, top, right, bottom = font.getbbox(text)
        width = abs(right - left)
        height =  abs(top - bottom)
        return [width, height]
    elif hasattr(font, 'getoffset'):
        return [x + y for x, y in zip(font.getsize(text), font.getoffset(text))]
    elif hasattr(font, 'getsize'):
        return font.getsize(text)
    else:
        raise Exception('Font has not known properties to get its size')

def noise_arcs(draw, image):
    fg_color = '#001100'
    size = image.size
    draw.arc([-20, -20, size[0], 20], 0, 295, fill=fg_color)
    draw.line([-20, 20, size[0] + 20, size[1] - 20], fill=fg_color)
    draw.line([-20, 0, size[0] + 20, size[1]], fill=fg_color)
    return draw


def noise_dots(draw, image):
    fg_color = '#001100'
    size = image.size
    for p in range(int(size[0] * size[1] * 0.1)):
        draw.point((random.randint(0, size[0]), random.randint(0, size[1])),
                   fill=fg_color)
    return draw


def make_image(text, code):
    from_top = 4
    font_path = os.path.normpath(os.path.join(os.path.dirname(__file__), 'fonts/Vera.ttf'))
    font_size = 22
    punctuation = '''_"',.;:-'''
    foreground_color = '#001100'
    background_color = '#ffffff'
    letter_rotation = (-35, 35)
    pregen_path = settings.STATIC_ROOT + '/captcha/'

    if not os.path.exists(pregen_path):
        os.makedirs(pregen_path)

    if font_path.lower().strip().endswith('ttf'):
        font = ImageFont.truetype(font_path, font_size)
    else:
        font = ImageFont.load(font_path)

    size = getsize(font, text)

    size = (size[0] * 2, int(size[1] * 1.4))
    image = Image.new('RGB', size, background_color)

    xpos = 2

    charlist = []
    for char in text:
        if char in punctuation and len(charlist) >= 1:
            charlist[-1] += char
        else:
            charlist.append(char)

    for char in charlist:
        fgimage = Image.new('RGB', size, foreground_color)
        charimage = Image.new('L', getsize(font, ' %s ' % char), '#000000')
        chardraw = ImageDraw.Draw(charimage)
        chardraw.text((0, 0), ' %s ' % char, font=font, fill='#ffffff')
        if letter_rotation:
            charimage = charimage.rotate(random.randrange(*letter_rotation), expand=0, resample=Image.BICUBIC)
            #if PIL_VERSION >= 116:
            #    charimage = charimage.rotate(random.randrange(*letter_rotation), expand=0, resample=Image.BICUBIC)
            #else:
            #    charimage = charimage.rotate(random.randrange(*letter_rotation), resample=Image.BICUBIC)
        charimage = charimage.crop(charimage.getbbox())
        maskimage = Image.new('L', size)

        maskimage.paste(charimage, (xpos, from_top, xpos + charimage.size[0], from_top + charimage.size[1]))
        size = maskimage.size
        image = Image.composite(fgimage, image, maskimage)
        xpos = xpos + 2 + charimage.size[0]

    image = image.crop((0, 0, xpos + 1, size[1]))
    draw = ImageDraw.Draw(image)

    for f in [noise_arcs, noise_dots]:
        draw = f(draw, image)

    image = image.filter(ImageFilter.SMOOTH)

    # Storing
    image_path = pregen_path
    path = str(os.path.join(image_path, '%s.png' % code))
    out = open(path, 'wb')
    image.save(out, "PNG")
    out.close()

    return image
