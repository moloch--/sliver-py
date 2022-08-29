#!/bin/bash

OUT_DIR="./src/sliver/pb"
IN_DIR="./sliver/protobuf"

rm -f $OUT_DIR/commonpb/common*.py
rm -f $OUT_DIR/sliverpb/sliver*.py
rm -f $OUT_DIR/clientpb/client*.py
rm -f $OUT_DIR/rpcpb/services*.py

# Common Protobuf
python -m grpc_tools.protoc -I $IN_DIR --python_out=./$OUT_DIR $IN_DIR/commonpb/common.proto

# Sliver Protobuf
python -m grpc_tools.protoc -I $IN_DIR --python_out=./$OUT_DIR $IN_DIR/sliverpb/sliver.proto

# Client Protobuf
python -m grpc_tools.protoc -I $IN_DIR --python_out=./$OUT_DIR $IN_DIR/clientpb/client.proto

# gRPC
python -m grpc_tools.protoc -I $IN_DIR --python_out=./$OUT_DIR --grpc_python_out=./$OUT_DIR $IN_DIR/rpcpb/services.proto

# Need to account for all OSes. For some reason MacOS takes an argument with -i.
if [[ "$OSTYPE" == "darwin"* ]]; then
    # Re-write commonpb imports
    sed -i "" -e \
        "s/from commonpb import common_pb2 as commonpb_dot_common__pb2/from ..commonpb import common_pb2 as commonpb_dot_common__pb2/g" \
        "$OUT_DIR/sliverpb/"*.py
    sed -i "" -e \
        "s/from commonpb import common_pb2 as commonpb_dot_common__pb2/from ..commonpb import common_pb2 as commonpb_dot_common__pb2/g" \
        "$OUT_DIR/clientpb/"*.py
    sed -i "" -e \
        "s/from commonpb import common_pb2 as commonpb_dot_common__pb2/from ..commonpb import common_pb2 as commonpb_dot_common__pb2/g" \
        "$OUT_DIR/rpcpb/"*.py

    # Re-write sliverpb / clientpb imports
    sed -i "" -e \
        "s/from sliverpb import sliver_pb2 as sliverpb_dot_sliver__pb2/from ..sliverpb import sliver_pb2 as sliverpb_dot_sliver__pb2/g" \
        "$OUT_DIR/rpcpb/"*.py
    sed -i "" -e \
        "s/from clientpb import client_pb2 as clientpb_dot_client__pb2/from ..clientpb import client_pb2 as clientpb_dot_client__pb2/g" \
        "$OUT_DIR/rpcpb/"*.py
else
     # Re-write commonpb imports
    sed -i -e \
        "s/from commonpb import common_pb2 as commonpb_dot_common__pb2/from ..commonpb import common_pb2 as commonpb_dot_common__pb2/g" \
        "$OUT_DIR/sliverpb/"*.py
    sed -i -e \
        "s/from commonpb import common_pb2 as commonpb_dot_common__pb2/from ..commonpb import common_pb2 as commonpb_dot_common__pb2/g" \
        "$OUT_DIR/clientpb/"*.py
    sed -i -e \
        "s/from commonpb import common_pb2 as commonpb_dot_common__pb2/from ..commonpb import common_pb2 as commonpb_dot_common__pb2/g" \
        "$OUT_DIR/rpcpb/"*.py

    # Re-write sliverpb / clientpb imports
    sed -i -e \
        "s/from sliverpb import sliver_pb2 as sliverpb_dot_sliver__pb2/from ..sliverpb import sliver_pb2 as sliverpb_dot_sliver__pb2/g" \
        "$OUT_DIR/rpcpb/"*.py
    sed -i -e \
        "s/from clientpb import client_pb2 as clientpb_dot_client__pb2/from ..clientpb import client_pb2 as clientpb_dot_client__pb2/g" \
        "$OUT_DIR/rpcpb/"*.py
fi