import csv
import os
from pathlib import Path
from typing import Union, List, Generator


class MetaRow:
    """Class represented meta markup row structure"""

    Id: int
    FileID: str
    Domain: str
    RepoName: str
    FilePath: str
    LineStart: int
    LineEnd: int
    GroundTruth: str
    WithWords: str
    ValueStart: int
    ValueEnd: int
    InURL: str
    InRuntimeParameter: str
    CharacterSet: str
    CryptographyKey: str
    PredefinedPattern: str
    VariableNameType: str
    Entropy: float
    Length: int
    Base64Encode: str
    HexEncode: str
    URLEncode: str
    Category: str

    def __init__(self, row: dict):
        if not isinstance(row, dict):
            raise RuntimeError(f"ERROR: wrong row {row}")
        for key, typ in self.__annotations__.items():
            val = None
            if key.startswith("__"):
                continue
            row_val = row.get(key)
            if row_val is not None:
                if typ is int or typ is float:
                    if row_val:
                        val = typ(row_val)
                    else:
                        val = -1
                elif typ is str and isinstance(row_val, str):
                    val = row_val
                self.__setattr__(key, val)
        if self.LineStart > self.LineEnd:
            raise RuntimeError(f"ERROR: LineStart must be lower than LineEnd {row}")

    def __str__(self) -> str:
        dict_values = self.__dict__.values()
        _str = ','.join(str(x) for x in dict_values)
        return _str

    def __repr__(self):
        return str(self)


def _meta_from_file(meta_path: Path) -> Generator[dict, None, None]:
    if ".csv" != meta_path.suffix:
        # *.csv.orig artifacts after git merge
        print(f"WARNING: skip {meta_path} file")
        return
    with open(meta_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not isinstance(row, dict):
                raise RuntimeError(f"ERROR: wrong row '{row}' in {meta_path}")
            yield row


def _meta_from_dir(meta_path: Path) -> Generator[dict, None, None]:
    for root, dirs, files in os.walk(meta_path):
        root_path = Path(root)
        for file in files:
            yield from _meta_from_file(root_path / file)
        # meta dir is flat
        break


def read_meta(meta_dir: Union[str, Path]) -> List[MetaRow]:
    meta = []
    meta_ids = set()
    if isinstance(meta_dir, str):
        meta_dir = Path(meta_dir)
    if not meta_dir.exists():
        raise RuntimeError(f"ERROR: {meta_dir} does not exist")
    if meta_dir.is_dir():
        source_gen = _meta_from_dir
    elif meta_dir.is_file():
        source_gen = _meta_from_file
    else:
        raise RuntimeError(f"ERROR: unsupported {meta_dir} type")

    for row in source_gen(meta_dir):
        meta_row = MetaRow(row)
        if meta_row.Id in meta_ids:
            raise RuntimeError(f"ERROR: duplicate Id row {row}")
        meta_ids.add(meta_row.Id)
        meta.append(meta_row)

    return meta