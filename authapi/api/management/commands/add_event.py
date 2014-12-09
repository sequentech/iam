from django.core.management.base import BaseCommand, CommandError, make_option
from api.models import AuthEvent
from authmethods import METHODS
import json

class Command(BaseCommand):
    help = '''Create a default config for authevent event and create authevent.
Example(config): add_event --type sms-code --generate
Example(create): add_event --config config.json --meta meta.json -t sms-code'''
    option_list = BaseCommand.option_list + (
            make_option(
                '-c',
                '--config',
                dest = 'conf',
                help = "specify config file", 
                metavar = "FILE"
            ),
            make_option(
                '-m',
                '--meta',
                dest = 'meta',
                help = "specify metadata file", 
                metavar = "FILE"
            ),
            make_option(
                '-n',
                '--name',
                dest = 'name',
                help = "specify name of event", 
                metavar = str
            ),
            make_option(
                '-t',
                '--type',
                dest = 'type',
                help = "type of authmethod", 
                metavar = str,
                choices = tuple(METHODS.keys())
            ),
            make_option(
                '-g',
                '--generate',
                action="store_true",
                dest = 'gen',
                help = "create default config files", 
            ),
    )

    def add_arguments(self, parser):
        parser.add_argument('AuthEvent_id', nargs='+', type=file)

    def handle(self, *args, **options):
        if options['gen'] and options['type']:
            try:
                config = METHODS.get(options['type']).TPL_CONFIG
                meta = METHODS.get(options['type']).METADATA_DEFAULT
                with open('config.json', 'w') as f1:
                    json.dump(config, f1, indent=4)
                with open('meta.json', 'w') as f2:
                    json.dump(meta, f2, indent=4)
                return
            except:
                print("Error creating default configuration files.")
        elif options['conf'] and options['meta'] and options['name'] and options['type']:
            conf = open(options['conf'], 'r')
            meta = open(options['meta'], 'r')
            ae = AuthEvent(name=options['name'], auth_method=options['type'],
                    auth_method_config=json.dumps(json.load(conf)),
                    metadata=json.dumps(json.load(meta)))
            ae.save()
        else:
            print(self.help)
            print('ERROR: Read the help and try again.')
