#!/bin/bash

virtualenv venv
source venv/bin/activate

OUT_DIR="./src/sliver/pb"
IN_DIR="./sliver/protobuf"

rm -rf $OUT_DIR/commonpb
rm -rf $OUT_DIR/sliverpb
rm -rf $OUT_DIR/clientpb
rm -rf $OUT_DIR/rpcpb

# Common Protobuf
python -m grpc_tools.protoc -I $IN_DIR --python_out=./$OUT_DIR $IN_DIR/commonpb/common.proto

# Sliver Protobuf
python -m grpc_tools.protoc -I $IN_DIR --python_out=./$OUT_DIR $IN_DIR/sliverpb/sliver.proto

# Client Protobuf
python -m grpc_tools.protoc -I $IN_DIR --python_out=./$OUT_DIR $IN_DIR/clientpb/client.proto

# gRPC
python -m grpc_tools.protoc -I $IN_DIR --python_out=./$OUT_DIR --grpc_python_out=./$OUT_DIR $IN_DIR/rpcpb/services.proto


# Re-write commonpb imports
sed -i "" -e \
    "s/from commonpb import common_pb2 as commonpb_dot_common__pb2/from ..commonpb import common_pb2 as commonpb_dot_common__pb2/g" \
    "$OUT_DIR/sliverpb/"*
sed -i "" -e \
    "s/from commonpb import common_pb2 as commonpb_dot_common__pb2/from ..commonpb import common_pb2 as commonpb_dot_common__pb2/g" \
    "$OUT_DIR/clientpb/"*
sed -i "" -e \
    "s/from commonpb import common_pb2 as commonpb_dot_common__pb2/from ..commonpb import common_pb2 as commonpb_dot_common__pb2/g" \
    "$OUT_DIR/rpcpb/"*

# Re-write sliverpb / clientpb imports
sed -i "" -e \
    "s/from sliverpb import sliver_pb2 as sliverpb_dot_sliver__pb2/from ..sliverpb import sliver_pb2 as sliverpb_dot_sliver__pb2/g" \
    "$OUT_DIR/rpcpb/"*
sed -i "" -e \
    "s/from clientpb import client_pb2 as clientpb_dot_client__pb2/from ..clientpb import client_pb2 as clientpb_dot_client__pb2/g" \
    "$OUT_DIR/rpcpb/"*
