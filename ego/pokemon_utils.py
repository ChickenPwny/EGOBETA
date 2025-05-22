import random
import logging
from ego.models import Customers

logger = logging.getLogger(__name__)

def generate_unique_pokemon_name():
    POKEMON_NAMES = [
        "Bulbasaur", "Ivysaur", "Venusaur", "Charmander", "Charmeleon", "Charizard",
        "Squirtle", "Wartortle", "Blastoise", "Pikachu", "Raichu", "Jigglypuff",
        "Meowth", "Psyduck", "Snorlax", "Mewtwo", "Mew"
    ]

    while True:
        name = random.choice(POKEMON_NAMES)
        logger.debug(f"Trying Pokémon name: {name}")  # Debugging
        if not Customers.objects.filter(nameProject=name).exists():
            logger.debug(f"Selected Pokémon name: {name}")  # Debugging
            return name
   