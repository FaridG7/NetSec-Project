from pathlib import Path
import json

from modules.exceptions import BadOptionsFormat, OptionsNotFound

class LoadOptions:
    def load_options(self)->dict[str, str]:
        path = Path('files') / 'options.json'
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            try:
                with open(path) as f:
                    options =  json.load(f)
                    #TODO: validate options format
            except json.JSONDecodeError:
                raise BadOptionsFormat
        else:
            raise OptionsNotFound
