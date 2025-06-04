from django.core.management.base import BaseCommand
from ego.models import Pokemon
from ego.pokemon_utils import POKEMON_NAMES  # Import the Pokémon list

class Command(BaseCommand):
    help = "Populate the Pokemon model with the first 151 Pokémon names"

    def handle(self, *args, **kwargs):
        for name in POKEMON_NAMES:
            Pokemon.objects.get_or_create(name=name)

        self.stdout.write(self.style.SUCCESS("Successfully populated Pokémon names"))
