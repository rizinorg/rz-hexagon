# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: LGPL-3.0-only

import json
import logging as log
import re
import subprocess

from pathlib import Path


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class PathHandler(metaclass=Singleton):
    paths = {}

    def __init__(self) -> None:
        try:
            res = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True, stdout=subprocess.PIPE)
        except subprocess.CalledProcessError:
            log.fatal("Could not get repository top level directory.")
            exit(1)
        repo_root = res.stdout.decode("utf8").strip("\n")
        # The main directories
        self.paths["{REPO_ROOT}"] = Path(repo_root)
        paths_file = self.paths["{REPO_ROOT}"].joinpath("paths.json")

        # Load variables
        with open(paths_file) as f:
            paths = json.load(f)
        self.output = paths["output_files"]
        self.input = paths["input_file_dirs"]
        self.gen = paths["generator_files"]

        for p_name, path in paths["path_variables"].items():
            resolved = path
            for var_id in re.findall(r"\{.+}", resolved):
                if var_id not in self.paths:
                    log.fatal(
                        f"{var_id} hasn't been added to the paths.json"
                        " yet. The var must be defined in a previous entry."
                    )
                    exit(1)
                resolved = Path(re.sub(var_id, str(self.paths[var_id]), resolved))
                log.debug(f"Set {p_name} = {resolved}")
                if not resolved.exists() and resolved.is_dir():
                    resolved.mkdir(parents=True)
                self.paths[p_name] = resolved

    def get_path(self, name: str) -> Path:
        if name not in self.paths:
            raise ValueError(f"Path variable {name} has no path saved.")
        return self.paths[name]

    def complete_path(self, path_str: str) -> Path:
        resolved = path_str
        for p_name in re.findall(r"\{.+}", path_str):
            resolved = re.sub(p_name, str(self.get_path(p_name)), resolved)
        return Path(resolved)

    def get_gen_file(self, name: str) -> Path:
        return self.complete_path(self.gen[name])

    def get_input_dir(self, name: str) -> Path:
        return self.complete_path(self.input[name])

    def get_output_file(self, name: str) -> Path:
        resolved = self.complete_path(self.output[name])
        if not resolved.parent.exists():
            resolved.parent.mkdir(parents=True)
        return resolved
