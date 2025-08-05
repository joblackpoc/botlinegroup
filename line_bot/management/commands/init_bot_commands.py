# line_bot/management/commands/init_bot_commands.py

from django.core.management.base import BaseCommand
from django.db import transaction
from line_bot.models import BotCommand


class Command(BaseCommand):
    help = 'Initialize default bot commands'

    def handle(self, *args, **options):
        self.stdout.write('Initializing bot commands...')
        
        commands = [
            # User commands
            {
                'command': 'help',
                'description': 'Show available commands',
                'permission_level': 'user',
            },
            {
                'command': 'status',
                'description': 'Check your account status',
                'permission_level': 'user',
            },
            {
                'command': 'validateme',
                'description': 'Validate yourself with group password',
                'permission_level': 'user',
            },
            {
                'command': 'groupinfo',
                'description': 'Show group information',
                'permission_level': 'user',
            },
            
            # Admin commands
            {
                'command': 'setpassword',
                'description': 'Set group password',
                'permission_level': 'admin',
            },
            {
                'command': 'changepassword',
                'description': 'Change group password',
                'permission_level': 'admin',
            },
            {
                'command': 'listmembers',
                'description': 'List group members',
                'permission_level': 'admin',
            },
            {
                'command': 'removemember',
                'description': 'Remove a member from group',
                'permission_level': 'admin',
            },
            {
                'command': 'commands',
                'description': 'List all available commands',
                'permission_level': 'admin',
            },
            {
                'command': 'stats',
                'description': 'Show bot statistics',
                'permission_level': 'admin',
            },
            {
                'command': 'security',
                'description': 'Show security status',
                'permission_level': 'admin',
            },
            {
                'command': 'approve',
                'description': 'Approve pending user',
                'permission_level': 'admin',
            },
            {
                'command': 'reject',
                'description': 'Reject pending user',
                'permission_level': 'admin',
            },
            
            # Superuser commands
            {
                'command': 'broadcast',
                'description': 'Send message to all groups',
                'permission_level': 'superuser',
            },
        ]
        
        created_count = 0
        updated_count = 0
        
        with transaction.atomic():
            for cmd_data in commands:
                command, created = BotCommand.objects.update_or_create(
                    command=cmd_data['command'],
                    defaults={
                        'description': cmd_data['description'],
                        'permission_level': cmd_data['permission_level'],
                        'is_active': True,
                    }
                )
                
                if created:
                    created_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'Created command: /{command.command}')
                    )
                else:
                    updated_count += 1
                    self.stdout.write(
                        self.style.WARNING(f'Updated command: /{command.command}')
                    )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'\nCompleted! Created {created_count} new commands, '
                f'updated {updated_count} existing commands.'
            )
        )