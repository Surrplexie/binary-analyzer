from .base import UnpackResult
from .upx import unpack_upx

UNPACK_RECIPES = {
    "UPX": unpack_upx,
}


def attempt_unpack(packer_name: str, file_path: str, output_dir: str) -> UnpackResult:
    recipe = UNPACK_RECIPES.get(packer_name)
    if recipe is None:
        return UnpackResult(
            attempted=False,
            performed=False,
            packer=packer_name,
            error=f"no unpack recipe for {packer_name}",
        )
    return recipe(file_path, output_dir)
