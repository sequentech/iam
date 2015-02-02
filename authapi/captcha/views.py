import os
import json
import random
import string
from django.views.generic import View
from django.http import HttpResponse
from django.conf import settings
from djcelery import celery

try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter
except ImportError:
    import Image
    import ImageDraw
    import ImageFont
    import ImageFilter

from .models import Captcha


def newcaptcha():
    letters = string.ascii_uppercase + string.digits

    code = ''.join(random.choice(letters) for _ in range(10))
    challenge = ''.join(random.choice(letters) for _ in range(4))

    make_image(challenge, code)

    fname = code + '.png'
    path = '/static/captcha/%s' % fname

    c = Captcha(code=code, challenge=challenge, path=path)
    c.save()

    data = {
        'captcha_code': c.code,
        'image_url': c.path
    }
    return data


@celery.task
def generate_captcha(amount=1):
    from captcha.views import newcaptcha
    repeat = 0
    while repeat < amount:
        newcaptcha()
        repeat += 1


class NewCaptcha(View):
    def get(self, request):
        # TODO, think about limits to prevent lots of calls because this
        # creates an image file and we can get out of disk space
        data = newcaptcha()
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
new_captcha = NewCaptcha.as_view()


def getsize(font, text):
    if hasattr(font, 'getoffset'):
        return [x + y for x, y in zip(font.getsize(text), font.getoffset(text))]
    else:
        return font.getsize(text)


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
