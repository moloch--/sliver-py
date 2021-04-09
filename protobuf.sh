#!/bin/bash

virtualenv venv
source venv/bin/activate


# Common Protobuf
python -m grpc_tools.protoc -I ./sliver/protobuf --python_out=./src/sliver/pb ./sliver/protobuf/commonpb/common.proto

# Sliver Protobuf
python -m grpc_tools.protoc -I ./sliver/protobuf --python_out=./src/sliver/pb ./sliver/protobuf/sliverpb/sliver.proto

# Client Protobuf
python -m grpc_tools.protoc -I ./sliver/protobuf --python_out=./src/sliver/pb ./sliver/protobuf/clientpb/client.proto

# gRPC
python -m grpc_tools.protoc -I ./sliver/protobuf --python_out=./src/sliver/pb --grpc_python_out=./src/sliver/pb ./sliver/protobuf/rpcpb/services.proto

