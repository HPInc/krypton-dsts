// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.15.8
// source: dsts.proto

package dstsprotos

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_dsts_proto protoreflect.FileDescriptor

var file_dsts_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x6b, 0x72,
	0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x1a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x5f,
	0x6b, 0x65, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x16, 0x65, 0x6e, 0x72, 0x6f, 0x6c,
	0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x0e, 0x61, 0x70, 0x70, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x32, 0x93, 0x0a, 0x0a, 0x09, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x53, 0x54, 0x53, 0x12,
	0x57, 0x0a, 0x0c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x12,
	0x21, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x43,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x22, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74,
	0x73, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x4e, 0x0a, 0x09, 0x47, 0x65, 0x74, 0x44,
	0x65, 0x76, 0x69, 0x63, 0x65, 0x12, 0x1e, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e,
	0x64, 0x73, 0x74, 0x73, 0x2e, 0x47, 0x65, 0x74, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e,
	0x64, 0x73, 0x74, 0x73, 0x2e, 0x47, 0x65, 0x74, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x54, 0x0a, 0x0b, 0x4c, 0x69, 0x73, 0x74,
	0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73, 0x12, 0x20, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f,
	0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x44, 0x65, 0x76, 0x69, 0x63,
	0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x6b, 0x72, 0x79, 0x70,
	0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x44, 0x65, 0x76,
	0x69, 0x63, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x57,
	0x0a, 0x0c, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x12, 0x21,
	0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x22, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73,
	0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x57, 0x0a, 0x0c, 0x44, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x12, 0x21, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f,
	0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x44, 0x65, 0x76,
	0x69, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x22, 0x2e, 0x6b, 0x72, 0x79,
	0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00,
	0x12, 0x5a, 0x0a, 0x0d, 0x47, 0x65, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x4b, 0x65,
	0x79, 0x12, 0x22, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73,
	0x2e, 0x47, 0x65, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x23, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e,
	0x64, 0x73, 0x74, 0x73, 0x2e, 0x47, 0x65, 0x74, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x4b,
	0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x72, 0x0a, 0x15,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e, 0x74,
	0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x2a, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e,
	0x64, 0x73, 0x74, 0x73, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x45, 0x6e, 0x72, 0x6f, 0x6c,
	0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x2b, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73,
	0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e,
	0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00,
	0x12, 0x69, 0x0a, 0x12, 0x47, 0x65, 0x74, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e,
	0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x27, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e,
	0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x47, 0x65, 0x74, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d,
	0x65, 0x6e, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x28, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x47,
	0x65, 0x74, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x72, 0x0a, 0x15, 0x44,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x54,
	0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x2a, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64,
	0x73, 0x74, 0x73, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c,
	0x6d, 0x65, 0x6e, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x2b, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e, 0x74,
	0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12,
	0x78, 0x0a, 0x17, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x45, 0x6e, 0x72, 0x6f, 0x6c,
	0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x2c, 0x2e, 0x6b, 0x72, 0x79,
	0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2d, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74,
	0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x45, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x6d, 0x65, 0x6e, 0x74, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x3f, 0x0a, 0x04, 0x50, 0x69, 0x6e,
	0x67, 0x12, 0x19, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73,
	0x2e, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1a, 0x2e, 0x6b,
	0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x50, 0x69, 0x6e, 0x67,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x84, 0x01, 0x0a, 0x1d, 0x47,
	0x65, 0x74, 0x41, 0x70, 0x70, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x12, 0x2f, 0x2e, 0x6b,
	0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x41, 0x70, 0x70, 0x41,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x68, 0x61,
	0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x30, 0x2e,
	0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x41, 0x70, 0x70,
	0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x68,
	0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x00, 0x12, 0x64, 0x0a, 0x0f, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x41, 0x70, 0x70, 0x12, 0x26, 0x2e, 0x6b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64,
	0x73, 0x74, 0x73, 0x2e, 0x41, 0x70, 0x70, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x27, 0x2e, 0x6b,
	0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2e, 0x64, 0x73, 0x74, 0x73, 0x2e, 0x41, 0x70, 0x70, 0x41,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x2f, 0x5a, 0x2d, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x61, 0x7a, 0x63, 0x2e, 0x65, 0x78, 0x74, 0x2e, 0x68, 0x70, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x4b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x6e, 0x2f, 0x64, 0x73, 0x74, 0x73, 0x2f, 0x64, 0x73,
	0x74, 0x73, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_dsts_proto_goTypes = []interface{}{
	(*CreateDeviceRequest)(nil),                // 0: krypton.dsts.CreateDeviceRequest
	(*GetDeviceRequest)(nil),                   // 1: krypton.dsts.GetDeviceRequest
	(*ListDevicesRequest)(nil),                 // 2: krypton.dsts.ListDevicesRequest
	(*UpdateDeviceRequest)(nil),                // 3: krypton.dsts.UpdateDeviceRequest
	(*DeleteDeviceRequest)(nil),                // 4: krypton.dsts.DeleteDeviceRequest
	(*GetSigningKeyRequest)(nil),               // 5: krypton.dsts.GetSigningKeyRequest
	(*CreateEnrollmentTokenRequest)(nil),       // 6: krypton.dsts.CreateEnrollmentTokenRequest
	(*GetEnrollmentTokenRequest)(nil),          // 7: krypton.dsts.GetEnrollmentTokenRequest
	(*DeleteEnrollmentTokenRequest)(nil),       // 8: krypton.dsts.DeleteEnrollmentTokenRequest
	(*ValidateEnrollmentTokenRequest)(nil),     // 9: krypton.dsts.ValidateEnrollmentTokenRequest
	(*PingRequest)(nil),                        // 10: krypton.dsts.PingRequest
	(*AppAuthenticationChallengeRequest)(nil),  // 11: krypton.dsts.AppAuthenticationChallengeRequest
	(*AppAuthenticationRequest)(nil),           // 12: krypton.dsts.AppAuthenticationRequest
	(*CreateDeviceResponse)(nil),               // 13: krypton.dsts.CreateDeviceResponse
	(*GetDeviceResponse)(nil),                  // 14: krypton.dsts.GetDeviceResponse
	(*ListDevicesResponse)(nil),                // 15: krypton.dsts.ListDevicesResponse
	(*UpdateDeviceResponse)(nil),               // 16: krypton.dsts.UpdateDeviceResponse
	(*DeleteDeviceResponse)(nil),               // 17: krypton.dsts.DeleteDeviceResponse
	(*GetSigningKeyResponse)(nil),              // 18: krypton.dsts.GetSigningKeyResponse
	(*CreateEnrollmentTokenResponse)(nil),      // 19: krypton.dsts.CreateEnrollmentTokenResponse
	(*GetEnrollmentTokenResponse)(nil),         // 20: krypton.dsts.GetEnrollmentTokenResponse
	(*DeleteEnrollmentTokenResponse)(nil),      // 21: krypton.dsts.DeleteEnrollmentTokenResponse
	(*ValidateEnrollmentTokenResponse)(nil),    // 22: krypton.dsts.ValidateEnrollmentTokenResponse
	(*PingResponse)(nil),                       // 23: krypton.dsts.PingResponse
	(*AppAuthenticationChallengeResponse)(nil), // 24: krypton.dsts.AppAuthenticationChallengeResponse
	(*AppAuthenticationResponse)(nil),          // 25: krypton.dsts.AppAuthenticationResponse
}
var file_dsts_proto_depIdxs = []int32{
	0,  // 0: krypton.dsts.DeviceSTS.CreateDevice:input_type -> krypton.dsts.CreateDeviceRequest
	1,  // 1: krypton.dsts.DeviceSTS.GetDevice:input_type -> krypton.dsts.GetDeviceRequest
	2,  // 2: krypton.dsts.DeviceSTS.ListDevices:input_type -> krypton.dsts.ListDevicesRequest
	3,  // 3: krypton.dsts.DeviceSTS.UpdateDevice:input_type -> krypton.dsts.UpdateDeviceRequest
	4,  // 4: krypton.dsts.DeviceSTS.DeleteDevice:input_type -> krypton.dsts.DeleteDeviceRequest
	5,  // 5: krypton.dsts.DeviceSTS.GetSigningKey:input_type -> krypton.dsts.GetSigningKeyRequest
	6,  // 6: krypton.dsts.DeviceSTS.CreateEnrollmentToken:input_type -> krypton.dsts.CreateEnrollmentTokenRequest
	7,  // 7: krypton.dsts.DeviceSTS.GetEnrollmentToken:input_type -> krypton.dsts.GetEnrollmentTokenRequest
	8,  // 8: krypton.dsts.DeviceSTS.DeleteEnrollmentToken:input_type -> krypton.dsts.DeleteEnrollmentTokenRequest
	9,  // 9: krypton.dsts.DeviceSTS.ValidateEnrollmentToken:input_type -> krypton.dsts.ValidateEnrollmentTokenRequest
	10, // 10: krypton.dsts.DeviceSTS.Ping:input_type -> krypton.dsts.PingRequest
	11, // 11: krypton.dsts.DeviceSTS.GetAppAuthenticationChallenge:input_type -> krypton.dsts.AppAuthenticationChallengeRequest
	12, // 12: krypton.dsts.DeviceSTS.AuthenticateApp:input_type -> krypton.dsts.AppAuthenticationRequest
	13, // 13: krypton.dsts.DeviceSTS.CreateDevice:output_type -> krypton.dsts.CreateDeviceResponse
	14, // 14: krypton.dsts.DeviceSTS.GetDevice:output_type -> krypton.dsts.GetDeviceResponse
	15, // 15: krypton.dsts.DeviceSTS.ListDevices:output_type -> krypton.dsts.ListDevicesResponse
	16, // 16: krypton.dsts.DeviceSTS.UpdateDevice:output_type -> krypton.dsts.UpdateDeviceResponse
	17, // 17: krypton.dsts.DeviceSTS.DeleteDevice:output_type -> krypton.dsts.DeleteDeviceResponse
	18, // 18: krypton.dsts.DeviceSTS.GetSigningKey:output_type -> krypton.dsts.GetSigningKeyResponse
	19, // 19: krypton.dsts.DeviceSTS.CreateEnrollmentToken:output_type -> krypton.dsts.CreateEnrollmentTokenResponse
	20, // 20: krypton.dsts.DeviceSTS.GetEnrollmentToken:output_type -> krypton.dsts.GetEnrollmentTokenResponse
	21, // 21: krypton.dsts.DeviceSTS.DeleteEnrollmentToken:output_type -> krypton.dsts.DeleteEnrollmentTokenResponse
	22, // 22: krypton.dsts.DeviceSTS.ValidateEnrollmentToken:output_type -> krypton.dsts.ValidateEnrollmentTokenResponse
	23, // 23: krypton.dsts.DeviceSTS.Ping:output_type -> krypton.dsts.PingResponse
	24, // 24: krypton.dsts.DeviceSTS.GetAppAuthenticationChallenge:output_type -> krypton.dsts.AppAuthenticationChallengeResponse
	25, // 25: krypton.dsts.DeviceSTS.AuthenticateApp:output_type -> krypton.dsts.AppAuthenticationResponse
	13, // [13:26] is the sub-list for method output_type
	0,  // [0:13] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_dsts_proto_init() }
func file_dsts_proto_init() {
	if File_dsts_proto != nil {
		return
	}
	file_common_proto_init()
	file_device_proto_init()
	file_signing_key_proto_init()
	file_enrollment_token_proto_init()
	file_app_auth_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_dsts_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_dsts_proto_goTypes,
		DependencyIndexes: file_dsts_proto_depIdxs,
	}.Build()
	File_dsts_proto = out.File
	file_dsts_proto_rawDesc = nil
	file_dsts_proto_goTypes = nil
	file_dsts_proto_depIdxs = nil
}
