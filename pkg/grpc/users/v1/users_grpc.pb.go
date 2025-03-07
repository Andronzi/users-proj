// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: proto/v1/users.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	PublicUserService_Register_FullMethodName = "/users.v1.PublicUserService/Register"
	PublicUserService_Login_FullMethodName    = "/users.v1.PublicUserService/Login"
)

// PublicUserServiceClient is the client API for PublicUserService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PublicUserServiceClient interface {
	Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error)
	Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*LoginResponse, error)
}

type publicUserServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPublicUserServiceClient(cc grpc.ClientConnInterface) PublicUserServiceClient {
	return &publicUserServiceClient{cc}
}

func (c *publicUserServiceClient) Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(RegisterResponse)
	err := c.cc.Invoke(ctx, PublicUserService_Register_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *publicUserServiceClient) Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*LoginResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(LoginResponse)
	err := c.cc.Invoke(ctx, PublicUserService_Login_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PublicUserServiceServer is the server API for PublicUserService service.
// All implementations must embed UnimplementedPublicUserServiceServer
// for forward compatibility.
type PublicUserServiceServer interface {
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	Login(context.Context, *LoginRequest) (*LoginResponse, error)
	mustEmbedUnimplementedPublicUserServiceServer()
}

// UnimplementedPublicUserServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedPublicUserServiceServer struct{}

func (UnimplementedPublicUserServiceServer) Register(context.Context, *RegisterRequest) (*RegisterResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedPublicUserServiceServer) Login(context.Context, *LoginRequest) (*LoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedPublicUserServiceServer) mustEmbedUnimplementedPublicUserServiceServer() {}
func (UnimplementedPublicUserServiceServer) testEmbeddedByValue()                           {}

// UnsafePublicUserServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PublicUserServiceServer will
// result in compilation errors.
type UnsafePublicUserServiceServer interface {
	mustEmbedUnimplementedPublicUserServiceServer()
}

func RegisterPublicUserServiceServer(s grpc.ServiceRegistrar, srv PublicUserServiceServer) {
	// If the following call pancis, it indicates UnimplementedPublicUserServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&PublicUserService_ServiceDesc, srv)
}

func _PublicUserService_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PublicUserServiceServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PublicUserService_Register_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PublicUserServiceServer).Register(ctx, req.(*RegisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PublicUserService_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PublicUserServiceServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PublicUserService_Login_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PublicUserServiceServer).Login(ctx, req.(*LoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// PublicUserService_ServiceDesc is the grpc.ServiceDesc for PublicUserService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PublicUserService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "users.v1.PublicUserService",
	HandlerType: (*PublicUserServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Register",
			Handler:    _PublicUserService_Register_Handler,
		},
		{
			MethodName: "Login",
			Handler:    _PublicUserService_Login_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/v1/users.proto",
}

const (
	InternalUserService_GetProfile_FullMethodName     = "/users.v1.InternalUserService/GetProfile"
	InternalUserService_AssignAdmin_FullMethodName    = "/users.v1.InternalUserService/AssignAdmin"
	InternalUserService_CreateEmployee_FullMethodName = "/users.v1.InternalUserService/CreateEmployee"
	InternalUserService_BanUser_FullMethodName        = "/users.v1.InternalUserService/BanUser"
)

// InternalUserServiceClient is the client API for InternalUserService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type InternalUserServiceClient interface {
	GetProfile(ctx context.Context, in *GetProfileRequest, opts ...grpc.CallOption) (*GetProfileResponse, error)
	AssignAdmin(ctx context.Context, in *AssignAdminRequest, opts ...grpc.CallOption) (*AssignAdminResponse, error)
	CreateEmployee(ctx context.Context, in *CreateEmployeeRequest, opts ...grpc.CallOption) (*CreateEmployeeResponse, error)
	BanUser(ctx context.Context, in *BanUserRequest, opts ...grpc.CallOption) (*BanUserResponse, error)
}

type internalUserServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewInternalUserServiceClient(cc grpc.ClientConnInterface) InternalUserServiceClient {
	return &internalUserServiceClient{cc}
}

func (c *internalUserServiceClient) GetProfile(ctx context.Context, in *GetProfileRequest, opts ...grpc.CallOption) (*GetProfileResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetProfileResponse)
	err := c.cc.Invoke(ctx, InternalUserService_GetProfile_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *internalUserServiceClient) AssignAdmin(ctx context.Context, in *AssignAdminRequest, opts ...grpc.CallOption) (*AssignAdminResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AssignAdminResponse)
	err := c.cc.Invoke(ctx, InternalUserService_AssignAdmin_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *internalUserServiceClient) CreateEmployee(ctx context.Context, in *CreateEmployeeRequest, opts ...grpc.CallOption) (*CreateEmployeeResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateEmployeeResponse)
	err := c.cc.Invoke(ctx, InternalUserService_CreateEmployee_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *internalUserServiceClient) BanUser(ctx context.Context, in *BanUserRequest, opts ...grpc.CallOption) (*BanUserResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(BanUserResponse)
	err := c.cc.Invoke(ctx, InternalUserService_BanUser_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// InternalUserServiceServer is the server API for InternalUserService service.
// All implementations must embed UnimplementedInternalUserServiceServer
// for forward compatibility.
type InternalUserServiceServer interface {
	GetProfile(context.Context, *GetProfileRequest) (*GetProfileResponse, error)
	AssignAdmin(context.Context, *AssignAdminRequest) (*AssignAdminResponse, error)
	CreateEmployee(context.Context, *CreateEmployeeRequest) (*CreateEmployeeResponse, error)
	BanUser(context.Context, *BanUserRequest) (*BanUserResponse, error)
	mustEmbedUnimplementedInternalUserServiceServer()
}

// UnimplementedInternalUserServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedInternalUserServiceServer struct{}

func (UnimplementedInternalUserServiceServer) GetProfile(context.Context, *GetProfileRequest) (*GetProfileResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetProfile not implemented")
}
func (UnimplementedInternalUserServiceServer) AssignAdmin(context.Context, *AssignAdminRequest) (*AssignAdminResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AssignAdmin not implemented")
}
func (UnimplementedInternalUserServiceServer) CreateEmployee(context.Context, *CreateEmployeeRequest) (*CreateEmployeeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateEmployee not implemented")
}
func (UnimplementedInternalUserServiceServer) BanUser(context.Context, *BanUserRequest) (*BanUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BanUser not implemented")
}
func (UnimplementedInternalUserServiceServer) mustEmbedUnimplementedInternalUserServiceServer() {}
func (UnimplementedInternalUserServiceServer) testEmbeddedByValue()                             {}

// UnsafeInternalUserServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to InternalUserServiceServer will
// result in compilation errors.
type UnsafeInternalUserServiceServer interface {
	mustEmbedUnimplementedInternalUserServiceServer()
}

func RegisterInternalUserServiceServer(s grpc.ServiceRegistrar, srv InternalUserServiceServer) {
	// If the following call pancis, it indicates UnimplementedInternalUserServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&InternalUserService_ServiceDesc, srv)
}

func _InternalUserService_GetProfile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetProfileRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InternalUserServiceServer).GetProfile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: InternalUserService_GetProfile_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InternalUserServiceServer).GetProfile(ctx, req.(*GetProfileRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _InternalUserService_AssignAdmin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AssignAdminRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InternalUserServiceServer).AssignAdmin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: InternalUserService_AssignAdmin_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InternalUserServiceServer).AssignAdmin(ctx, req.(*AssignAdminRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _InternalUserService_CreateEmployee_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateEmployeeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InternalUserServiceServer).CreateEmployee(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: InternalUserService_CreateEmployee_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InternalUserServiceServer).CreateEmployee(ctx, req.(*CreateEmployeeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _InternalUserService_BanUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BanUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(InternalUserServiceServer).BanUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: InternalUserService_BanUser_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(InternalUserServiceServer).BanUser(ctx, req.(*BanUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// InternalUserService_ServiceDesc is the grpc.ServiceDesc for InternalUserService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var InternalUserService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "users.v1.InternalUserService",
	HandlerType: (*InternalUserServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetProfile",
			Handler:    _InternalUserService_GetProfile_Handler,
		},
		{
			MethodName: "AssignAdmin",
			Handler:    _InternalUserService_AssignAdmin_Handler,
		},
		{
			MethodName: "CreateEmployee",
			Handler:    _InternalUserService_CreateEmployee_Handler,
		},
		{
			MethodName: "BanUser",
			Handler:    _InternalUserService_BanUser_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/v1/users.proto",
}
