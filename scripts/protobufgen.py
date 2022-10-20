import os
import pkg_resources
from pathlib import Path
from grpc_tools import protoc
from rich.console import Console


console = Console(log_time=False, log_path=False)
ROOT_DIR = Path(__file__).parents[1]
os.chdir(ROOT_DIR)

IN_DIR = ROOT_DIR / "sliver/protobuf"
OUT_DIR = ROOT_DIR / "src/sliver/pb"

COMMON_PROTO_PATH = IN_DIR / "commonpb/common.proto"
SLIVER_PROTO_PATH = IN_DIR / "sliverpb/sliver.proto"
CLIENT_PROTO_PATH = IN_DIR / "clientpb/client.proto"
GRPC_PROTO_PATH = IN_DIR / "rpcpb/services.proto"

# There is a more accurate way to do all of this using the ast module but this works for now
try:
    # Cleanup old files
    console.log("[bold green]Removing old generated files...")
    for file in OUT_DIR.glob("**/*.py"):
        if file.name.split("_")[0] in ["common", "sliver", "client", "services"]:
            file.unlink()
            console.log(f"Removed {file}")

    console.log("[bold green]Generating new files...")
    proto_pyd = pkg_resources.resource_filename("grpc_tools", "_proto")

    # Generate commonpb
    protoc.main(
        f"-I{proto_pyd} -I {IN_DIR.relative_to(ROOT_DIR)} --mypy_out=readable_stubs:{OUT_DIR} --python_out={OUT_DIR} {COMMON_PROTO_PATH.relative_to(ROOT_DIR)}".split()
    )
    console.log(f"Generated {COMMON_PROTO_PATH.name}")

    # Generate sliverpb
    protoc.main(
        f"-I{proto_pyd} -I {IN_DIR.relative_to(ROOT_DIR)} --mypy_out=readable_stubs:{OUT_DIR} --python_out={OUT_DIR} {SLIVER_PROTO_PATH.relative_to(ROOT_DIR)}".split()
    )
    console.log(f"Generated {SLIVER_PROTO_PATH.name}")

    # Generate clientpb
    protoc.main(
        f"-I{proto_pyd} -I {IN_DIR.relative_to(ROOT_DIR)} --mypy_out=readable_stubs:{OUT_DIR} --python_out={OUT_DIR} {CLIENT_PROTO_PATH.relative_to(ROOT_DIR)}".split()
    )
    console.log(f"Generated {CLIENT_PROTO_PATH.name}")

    # Generate rpcpb
    protoc.main(
        f"-I{proto_pyd} -I {IN_DIR.relative_to(ROOT_DIR)} --mypy_out=readable_stubs:{OUT_DIR} --mypy_grpc_out={OUT_DIR} --python_out={OUT_DIR} --grpc_python_out={OUT_DIR} {GRPC_PROTO_PATH.relative_to(ROOT_DIR)}".split()
    )
    console.log(f"Generated {GRPC_PROTO_PATH.name}")

    # Rewrite imports for py files
    console.log("[bold green]Rewriting imports for py files...")
    for file in OUT_DIR.glob("**/*.py"):
        if file.name.split("_")[0] in ["sliver", "client", "services"]:
            content = (
                file.read_text()
                .replace(
                    "from commonpb import common_pb2 as commonpb_dot_common__pb2",
                    "from ..commonpb import common_pb2 as commonpb_dot_common__pb2",
                )
                .replace(
                    "from sliverpb import sliver_pb2 as sliverpb_dot_sliver__pb2",
                    "from ..sliverpb import sliver_pb2 as sliverpb_dot_sliver__pb2",
                )
                .replace(
                    "from clientpb import client_pb2 as clientpb_dot_client__pb2",
                    "from ..clientpb import client_pb2 as clientpb_dot_client__pb2",
                )
            )
            # Need to make sure grpc.experimental is imported
            if file.name == "services_pb2_grpc.py":
                content = (content
                    .replace("grpc.Channel", "grpc.aio.Channel")
                    .replace("import grpc", "import grpc\nimport grpc.experimental")
                    )  # fmt: skip

            file.write_text(content)
            console.log(f"Rewrote imports for {file}")

    # Rewrite imports for pyi files
    console.log("[bold green]Rewriting imports for pyi files...")
    for file in OUT_DIR.glob("**/*.pyi"):
        if file.name.split("_")[0] in ["sliver", "client", "services"]:
            content = (
                file.read_text()
                .replace(
                    "import commonpb.common_pb2",
                    "from ..commonpb import common_pb2",
                )
                .replace(
                    "commonpb.common_pb2",
                    "common_pb2",
                )
                .replace(
                    "import sliverpb.sliver_pb2",
                    "from ..sliverpb import sliver_pb2",
                )
                .replace(
                    "sliverpb.sliver_pb2",
                    "sliver_pb2",
                )
                .replace(
                    "import clientpb.client_pb2",
                    "from ..clientpb import client_pb2",
                )
                .replace(
                    "clientpb.client_pb2",
                    "client_pb2",
                )
            )

            # Need to correct type hints. This is a hacky way to do it but it works
            if file.name == "services_pb2_grpc.pyi":
                content = content.replace("grpc.Channel", "grpc.aio.Channel")

            if file.name == "sliver_pb2.pyi":
                content = content.replace(
                    "from common_pb2 import", "from ..commonpb.common_pb2 import"
                )

            file.write_text(content)
            console.log(f"Rewrote imports for {file}")
except Exception as e:
    console.log("[bold red]Failed to generate files!")
    console.log(e)
