#ifndef RAW_CC
#define RAW_CC

#include <stdio.h>
#include <string.h>
#include "raw.h"


#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <net/ethernet.h> /* the L2 protocols */



#define BTPROTO_L2CAP 0
#define BTPROTO_HCI 1

#define SOL_HCI 0
#define HCI_FILTER 2

#define HCIGETDEVLIST _IOR('H', 210, int)
#define HCIGETDEVINFO _IOR('H', 211, int)

#define HCI_CHANNEL_RAW 0
#define HCI_CHANNEL_USER 1
#define HCI_CHANNEL_CONTROL 3

#define HCI_DEV_NONE 0xffff

#define HCI_MAX_DEV 16


enum
{
  HCI_UP,
  HCI_INIT,
  HCI_RUNNING,

  HCI_PSCAN,
  HCI_ISCAN,
  HCI_AUTH,
  HCI_ENCRYPT,
  HCI_INQUIRY,

  HCI_RAW,
};

typedef struct bdaddr_s {
  uint8_t b[6];

  bool operator<(const struct bdaddr_s& r) const {
    for(int i = 0; i < 6; i++) {
      if(b[i] > r.b[i]) {
        return false;
      }
    }
    return b[5] < r.b[5];
  }

} __attribute__((packed)) bdaddr_t;


struct sockaddr_hci
{
  sa_family_t hci_family;
  unsigned short hci_dev;
  unsigned short hci_channel;
};

struct hci_dev_req
{
  uint16_t dev_id;
  uint32_t dev_opt;
};

struct hci_dev_list_req
{
  uint16_t dev_num;
  struct hci_dev_req dev_req[0];
};

struct hci_dev_info
{
  uint16_t dev_id;
  char name[8];

  bdaddr_t bdaddr;

  uint32_t flags;
  uint8_t type;

  uint8_t features[8];

  uint32_t pkt_type;
  uint32_t link_policy;
  uint32_t link_mode;

  uint16_t acl_mtu;
  uint16_t acl_pkts;
  uint16_t sco_mtu;
  uint16_t sco_pkts;

  // hci_dev_stats
  uint32_t err_rx;
  uint32_t err_tx;
  uint32_t cmd_tx;
  uint32_t evt_rx;
  uint32_t acl_tx;
  uint32_t acl_rx;
  uint32_t sco_tx;
  uint32_t sco_rx;
  uint32_t byte_rx;
  uint32_t byte_tx;
};
#ifdef _WIN32
static char errbuf[1024];
#endif
const char* raw_strerror (int code) {
#ifdef _WIN32
	if (FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, code, 0, errbuf,
			1024, NULL)) {
		return errbuf;
	} else {
		strcpy (errbuf, "Unknown error");
		return errbuf;
	}
#else
	return strerror (code);
#endif
}

static uint16_t checksum (uint16_t start_with, unsigned char *buffer,
		size_t length) {
	unsigned i;
	uint32_t sum = start_with > 0 ? ~start_with & 0xffff : 0;

	for (i = 0; i < (length & ~1U); i += 2) {
		sum += (uint16_t) ntohs (*((uint16_t *) (buffer + i)));
		if (sum > 0xffff)
			sum -= 0xffff;
	}
	if (i < length) {
		sum += buffer [i] << 8;
		if (sum > 0xffff)
			sum -= 0xffff;
	}
	
	return ~sum & 0xffff;
}

namespace raw {

static Nan::Persistent<FunctionTemplate> SocketWrap_constructor;

void InitAll (Local<Object> exports) {
	ExportConstants (exports);
	ExportFunctions (exports);

	SocketWrap::Init (exports);
}

NODE_MODULE(raw, InitAll)

NAN_METHOD(CreateChecksum) {
	Nan::HandleScope scope;
	v8::Isolate* isolate = v8::Isolate::GetCurrent();
  	v8::Local<v8::Context> context = isolate->GetCurrentContext();
	
	if (info.Length () < 2) {
		Nan::ThrowError("At least one argument is required");
		return;
	}

	if (! info[0]->IsUint32 ()) {
		Nan::ThrowTypeError("Start with argument must be an unsigned integer");
		return;
	}
	
	uint32_t start_with = Nan::To<Uint32>(info[0]).ToLocalChecked()->Value();

	if (start_with > 65535) {
		Nan::ThrowRangeError("Start with argument cannot be larger than 65535");
		return;
	}

	if (! node::Buffer::HasInstance (info[1])) {
		Nan::ThrowTypeError("Buffer argument must be a node Buffer object");
		return;
	}
	
	Local<Object> buffer = Nan::To<Object>(info[1]).ToLocalChecked();
	char *data = node::Buffer::Data (buffer);
	size_t length = node::Buffer::Length (buffer);
	unsigned int offset = 0;
	
	if (info.Length () > 2) {
		if (! info[2]->IsUint32 ()) {
			Nan::ThrowTypeError("Offset argument must be an unsigned integer");
			return;
		}
		offset = Nan::To<Uint32>(info[2]).ToLocalChecked()->Value();
		if (offset >= length) {
			Nan::ThrowRangeError("Offset argument must be smaller than length of the buffer");
			return;
		}
	}
	
	if (info.Length () > 3) {
		if (! info[3]->IsUint32 ()) {
			Nan::ThrowTypeError("Length argument must be an unsigned integer");
			return;
		}
		unsigned int new_length = Nan::To<Uint32>(info[3]).ToLocalChecked()->Value();
		if (new_length > length) {
			Nan::ThrowRangeError("Length argument must be smaller than length of the buffer");
			return;
		}
		length = new_length;
	}
	
	uint16_t sum = checksum ((uint16_t) start_with,
			(unsigned char *) data + offset, length);

	Local<Integer> number = Nan::New<Uint32>(sum);
	
	info.GetReturnValue().Set(number);
}

NAN_METHOD(Htonl) {
	Nan::HandleScope scope;

	if (info.Length () < 1) {
		Nan::ThrowError("One arguments is required");
		return;
	}

	if (! info[0]->IsUint32 ()) {
		Nan::ThrowTypeError("Number must be a 32 unsigned integer");
		return;
	}

	unsigned int number = Nan::To<Uint32>(info[0]).ToLocalChecked()->Value();
	Local<Uint32> converted = Nan::New<Uint32>((unsigned int) htonl (number));

	info.GetReturnValue().Set(converted);
}

NAN_METHOD(Htons) {
	Nan::HandleScope scope;
	
	if (info.Length () < 1) {
		Nan::ThrowError("One arguments is required");
		return;
	}

	if (! info[0]->IsUint32 ()) {
		Nan::ThrowTypeError("Number must be a 16 unsigned integer");
		return;
	}
	
	unsigned int number = Nan::To<Uint32>(info[0]).ToLocalChecked()->Value();
	
	if (number > 65535) {
		Nan::ThrowRangeError("Number cannot be larger than 65535");
		return;
	}
	
	Local<Uint32> converted = Nan::New<Uint32>(htons (number));

	info.GetReturnValue().Set(converted);
}

NAN_METHOD(Ntohl) {
	Nan::HandleScope scope;
	
	if (info.Length () < 1) {
		Nan::ThrowError("One arguments is required");
		return;
	}

	if (! info[0]->IsUint32 ()) {
		Nan::ThrowTypeError("Number must be a 32 unsigned integer");
		return;
	}

	unsigned int number = Nan::To<Uint32>(info[0]).ToLocalChecked()->Value();
	Local<Uint32> converted = Nan::New<Uint32>((unsigned int) ntohl (number));

	info.GetReturnValue().Set(converted);
}

NAN_METHOD(Ntohs) {
	Nan::HandleScope scope;
	
	if (info.Length () < 1) {
		Nan::ThrowError("One arguments is required");
		return;
	}

	if (! info[0]->IsUint32 ()) {
		Nan::ThrowTypeError("Number must be a 16 unsigned integer");
		return;
	}
	
	unsigned int number = Nan::To<Uint32>(info[0]).ToLocalChecked()->Value();
	
	if (number > 65535) {
		Nan::ThrowRangeError("Number cannot be larger than 65535");
		return;
	}
	
	Local<Uint32> converted = Nan::New<Uint32>(htons (number));

	info.GetReturnValue().Set(converted);
}

void ExportConstants (Local<Object> target) {
	Local<Object> socket_level = Nan::New<Object>();
	Local<Object> socket_option = Nan::New<Object>();
	Local<Object> address_family = Nan::New<Object>();
	Local<Object> socket_protocol = Nan::New<Object>();

	Nan::Set(target, Nan::New("SocketLevel").ToLocalChecked(), socket_level);
	Nan::Set(target, Nan::New("SocketOption").ToLocalChecked(), socket_option);
	Nan::Set(target, Nan::New("AddressFamily").ToLocalChecked(), address_family);
	Nan::Set(target, Nan::New("SocketProtocol").ToLocalChecked(), socket_protocol);

	Nan::Set(socket_level, Nan::New("SOL_SOCKET").ToLocalChecked(), Nan::New<Number>(SOL_SOCKET));
	Nan::Set(socket_level, Nan::New("IPPROTO_IP").ToLocalChecked(), Nan::New<Number>(IPPROTO_IP + 0));
	Nan::Set(socket_level, Nan::New("IPPROTO_IPV6").ToLocalChecked(), Nan::New<Number>(IPPROTO_IPV6 + 0));

	Nan::Set(socket_option, Nan::New("SO_BROADCAST").ToLocalChecked(), Nan::New<Number>(SO_BROADCAST));
	Nan::Set(socket_option, Nan::New("SO_RCVBUF").ToLocalChecked(), Nan::New<Number>(SO_RCVBUF));
	Nan::Set(socket_option, Nan::New("SO_RCVTIMEO").ToLocalChecked(), Nan::New<Number>(SO_RCVTIMEO));
	Nan::Set(socket_option, Nan::New("SO_SNDBUF").ToLocalChecked(), Nan::New<Number>(SO_SNDBUF));
	Nan::Set(socket_option, Nan::New("SO_SNDTIMEO").ToLocalChecked(), Nan::New<Number>(SO_SNDTIMEO));

#ifdef __linux__
	Nan::Set(socket_option, Nan::New("SO_BINDTODEVICE").ToLocalChecked(), Nan::New<Number>(SO_BINDTODEVICE));	
	Nan::Set(socket_option, Nan::New("IP_MTU_DISCOVER").ToLocalChecked(), Nan::New<Number>(IP_MTU_DISCOVER));
	Nan::Set(socket_option, Nan::New("IP_PMTUDISC_DO").ToLocalChecked(), Nan::New<Number>(IP_PMTUDISC_DO));
	Nan::Set(socket_option, Nan::New("IP_PMTUDISC_DONT").ToLocalChecked(), Nan::New<Number>(IP_PMTUDISC_DONT));
#endif

	Nan::Set(socket_option, Nan::New("IP_HDRINCL").ToLocalChecked(), Nan::New<Number>(IP_HDRINCL));
	Nan::Set(socket_option, Nan::New("IP_OPTIONS").ToLocalChecked(), Nan::New<Number>(IP_OPTIONS));
	Nan::Set(socket_option, Nan::New("IP_TOS").ToLocalChecked(), Nan::New<Number>(IP_TOS));
	Nan::Set(socket_option, Nan::New("IP_TTL").ToLocalChecked(), Nan::New<Number>(IP_TTL));

#ifdef _WIN32
	Nan::Set(socket_option, Nan::New("IPV6_HDRINCL").ToLocalChecked(), Nan::New<Number>(IPV6_HDRINCL));
#endif
	Nan::Set(socket_option, Nan::New("IPV6_TTL").ToLocalChecked(), Nan::New<Number>(IPV6_UNICAST_HOPS));
	Nan::Set(socket_option, Nan::New("IPV6_UNICAST_HOPS").ToLocalChecked(), Nan::New<Number>(IPV6_UNICAST_HOPS));
	Nan::Set(socket_option, Nan::New("IPV6_V6ONLY").ToLocalChecked(), Nan::New<Number>(IPV6_V6ONLY));
	Nan::Set(socket_level, Nan::New("TCP_KEEPCNT").ToLocalChecked(), Nan::New<Number>(TCP_KEEPCNT));


	Nan::Set(address_family, Nan::New("AF_INET").ToLocalChecked(), Nan::New<Number>(AF_INET));
	Nan::Set(address_family, Nan::New("AF_INET6").ToLocalChecked(), Nan::New<Number>(AF_INET6));
	Nan::Set(address_family, Nan::New("PF_PACKET").ToLocalChecked(), Nan::New<Number>(PF_PACKET));
	Nan::Set(address_family, Nan::New("AF_BLUETOOTH").ToLocalChecked(), Nan::New<Number>(AF_BLUETOOTH));

	
	Nan::Set(socket_protocol, Nan::New("BTPROTO_HCI").ToLocalChecked(), Nan::New<Number>(BTPROTO_HCI));
	Nan::Set(socket_protocol, Nan::New("BTPROTO_L2CAP").ToLocalChecked(), Nan::New<Number>(BTPROTO_L2CAP));
}

void ExportFunctions (Local<Object> target) {
	Nan::Set(target, Nan::New("createChecksum").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(CreateChecksum)).ToLocalChecked());
	
	Nan::Set(target, Nan::New("htonl").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(Htonl)).ToLocalChecked());
	Nan::Set(target, Nan::New("htons").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(Htons)).ToLocalChecked());
	Nan::Set(target, Nan::New("ntohl").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(Ntohl)).ToLocalChecked());
	Nan::Set(target, Nan::New("ntohs").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(Ntohs)).ToLocalChecked());
}

void SocketWrap::Init (Local<Object> exports) {
	Nan::HandleScope scope;
	v8::Isolate* isolate = v8::Isolate::GetCurrent();
  	v8::Local<v8::Context> context = isolate->GetCurrentContext();

	Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(SocketWrap::New);
	tpl->SetClassName(Nan::New("SocketWrap").ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	Nan::SetPrototypeMethod(tpl, "close", Close);
	Nan::SetPrototypeMethod(tpl, "getOption", GetOption);
	Nan::SetPrototypeMethod(tpl, "pause", Pause);
	Nan::SetPrototypeMethod(tpl, "recv", Recv);
	Nan::SetPrototypeMethod(tpl, "send", Send);
	Nan::SetPrototypeMethod(tpl, "setOption", SetOption);
	Nan::SetPrototypeMethod(tpl, "bindBluetooth", BindBluetooth);

	SocketWrap_constructor.Reset(tpl);
	Nan::Set(exports, Nan::New("SocketWrap").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
}

SocketWrap::SocketWrap () {
	deconstructing_ = false;
}

SocketWrap::~SocketWrap () {
	deconstructing_ = true;
	this->CloseSocket ();
}

NAN_METHOD(SocketWrap::Close) {
	Nan::HandleScope scope;
	
	SocketWrap* socket = SocketWrap::Unwrap<SocketWrap> (info.This ());
	
	socket->CloseSocket ();

	Local<Value> args[1];
	args[0] = Nan::New<String>("close").ToLocalChecked();

	Nan::Call(Nan::New<String>("emit").ToLocalChecked(), info.This(), 1, args);

	info.GetReturnValue().Set(info.This());
}

void SocketWrap::CloseSocket (void) {
	Nan::HandleScope scope;
	v8::Isolate* isolate = v8::Isolate::GetCurrent();
  	v8::Local<v8::Context> context = isolate->GetCurrentContext();
	
	if (this->poll_initialised_) {
		uv_close ((uv_handle_t *) this->poll_watcher_, OnClose);
		closesocket (this->poll_fd_);
		this->poll_fd_ = INVALID_SOCKET;
		this->poll_initialised_ = false;
	}

	if (! this->deconstructing_) {
		MaybeLocal<Value> emit = handle()->Get(context, Nan::New<String>("_close").ToLocalChecked());
		Local<Function> cb = emit.ToLocalChecked().As<Function> ();

		cb->Call (context, handle(), 0, nullptr);
	}
}

int SocketWrap::CreateSocket (void) {
	if (this->poll_initialised_)
		return 0;
	
	this->poll_fd_ = socket (this->family_, SOCK_RAW, this->protocol_);
	
#ifdef __APPLE__
	/**
	 ** On MAC OS X platforms for non-privileged users wishing to utilise ICMP
	 ** a SOCK_DGRAM will be enough, so try to create this type of socket in
	 ** the case ICMP was requested.
	 **
	 ** More information can be found at:
	 **
	 **  https://developer.apple.com/library/mac/documentation/Darwin/Reference/Manpages/man4/icmp.4.html
	 **
	 **/
	if (this->poll_fd_ == INVALID_SOCKET && this->protocol_ == IPPROTO_ICMP)
		this->poll_fd_ = socket (this->family_, SOCK_DGRAM, this->protocol_);
#endif

	if (this->poll_fd_ == INVALID_SOCKET)
		return SOCKET_ERRNO;

	// make the socket non-blocking
#ifdef _WIN32
	unsigned long flag = 1;
	if (ioctlsocket (this->poll_fd_, FIONBIO, &flag) == SOCKET_ERROR)
		return SOCKET_ERRNO;
#else
	int flag = 1;
	if ((flag = fcntl (this->poll_fd_, F_GETFL, 0)) == SOCKET_ERROR)
		return SOCKET_ERRNO;
	if (fcntl (this->poll_fd_, F_SETFL, flag | O_NONBLOCK) == SOCKET_ERROR)
		return SOCKET_ERRNO;
#endif

	poll_watcher_ = new uv_poll_t;
	uv_poll_init_socket (uv_default_loop (), this->poll_watcher_,
			this->poll_fd_);
	this->poll_watcher_->data = this;
	uv_poll_start (this->poll_watcher_, UV_READABLE, IoEvent);
	
	this->poll_initialised_ = true;
	
	return 0;
}

NAN_METHOD(SocketWrap::GetOption) {
	Nan::HandleScope scope;
	v8::Isolate* isolate = v8::Isolate::GetCurrent();
  	v8::Local<v8::Context> context = isolate->GetCurrentContext();
	
	SocketWrap* socket = SocketWrap::Unwrap<SocketWrap> (info.This ());
	
	if (info.Length () < 3) {
		Nan::ThrowError("Three arguments are required");
		return;
	}

	if (! info[0]->IsNumber ()) {
		Nan::ThrowTypeError("Level argument must be a number");
		return;
	}

	if (! info[1]->IsNumber ()) {
		Nan::ThrowTypeError("Option argument must be a number");
		return;
	}

	int level = Nan::To<Uint32>(info[0]).ToLocalChecked()->Value();
	int option = Nan::To<Uint32>(info[1]).ToLocalChecked()->Value();
	SOCKET_OPT_TYPE val = NULL;
	unsigned int ival = 0;
	SOCKET_LEN_TYPE len;

	if (! node::Buffer::HasInstance (info[2])) {
		Nan::ThrowTypeError("Value argument must be a node Buffer object if length is provided");
		return;
	}
	
	Local<Object> buffer = Nan::To<Object>(info[2]).ToLocalChecked();
	val = node::Buffer::Data (buffer);

	if (! info[3]->IsInt32 ()) {
		Nan::ThrowTypeError("Length argument must be an unsigned integer");
		return;
	}

	len = (SOCKET_LEN_TYPE) node::Buffer::Length (buffer);

	int rc = getsockopt (socket->poll_fd_, level, option,
			(val ? val : (SOCKET_OPT_TYPE) &ival), &len);

	if (rc == SOCKET_ERROR) {
		Nan::ThrowError(node::ErrnoException(isolate, SOCKET_ERRNO, "getsockopt"));
		return;
	}
	
	Local<Number> got = Nan::New<Uint32>(len);
	
	info.GetReturnValue().Set(got);
}

void SocketWrap::HandleIOEvent (int status, int revents) {
	Nan::HandleScope scope;
	v8::Isolate* isolate = v8::Isolate::GetCurrent();
  	v8::Local<v8::Context> context = isolate->GetCurrentContext();

	if (status) {
		MaybeLocal<Value> emit = handle()->Get (context, Nan::New<String>("_error").ToLocalChecked());
		Local<Function> cb = emit.ToLocalChecked().As<Function> ();

		Local<Value> args[1];
		
		/**
		 ** The uv_last_error() function doesn't seem to be available in recent
		 ** libuv versions, and the uv_err_t variable also no longer appears to
		 ** be a structure.  This causes issues when working with both Node.js
		 ** 0.10 and 0.12.  So, for now, we will just give you the number.
		 **/
		args[0] = node::ErrnoException(isolate, abs(status), "epoll", "");

		cb->Call (context, handle(), 1, args);
	} else {
		MaybeLocal<Value> emit;

		if (revents & UV_READABLE)
			emit = handle()->Get (context, Nan::New<String>("_recvReady").ToLocalChecked());
		else
			emit = handle()->Get (context, Nan::New<String>("_sendReady").ToLocalChecked());


		Local<Function> cb = emit.ToLocalChecked().As<Function> ();

		cb->Call (context, handle(), 0, nullptr);
	}
}

NAN_METHOD(SocketWrap::New) {
	Nan::HandleScope scope;
	
	SocketWrap* socket = new SocketWrap ();
	int rc, family;
	
	if (info.Length () < 2) {
		Nan::ThrowError("Two arguments are required");
		return;
	}
	
	if (! info[0]->IsUint32 ()) {
		Nan::ThrowTypeError("Protocol argument must be an unsigned integer");
		return;
	}
	socket->protocol_ = Nan::To<Uint32>(info[0]).ToLocalChecked()->Value();

	if (! info[1]->IsUint32 ()) {
		Nan::ThrowTypeError("Address family argument must be an unsigned integer");
		return;
	}
	family = Nan::To<Uint32>(info[1]).ToLocalChecked()->Value();
	
	socket->family_ = family;
	
	socket->poll_initialised_ = false;
	
	socket->no_ip_header_ = false;

	rc = socket->CreateSocket ();
	if (rc != 0) {
		Nan::ThrowError(raw_strerror (rc));
		return;
	}

	socket->Wrap (info.This ());

	info.GetReturnValue().Set(info.This());
}

void SocketWrap::OnClose (uv_handle_t *handle) {
	delete handle;
}

NAN_METHOD(SocketWrap::Pause) {
	Nan::HandleScope scope;
	v8::Isolate* isolate = v8::Isolate::GetCurrent();
	
	SocketWrap* socket = SocketWrap::Unwrap<SocketWrap> (info.This ());

	if (info.Length () < 2) {
		Nan::ThrowError("Two arguments are required");
		return;
	}
	
	if (! info[0]->IsBoolean ()) {
		Nan::ThrowTypeError("Recv argument must be a boolean");
		return;
	}
	bool pause_recv = Nan::To<Boolean>(info[0]).ToLocalChecked()->Value();

	if (! info[1]->IsBoolean ()) {
		Nan::ThrowTypeError("Send argument must be a boolean");
		return;
	}
	bool pause_send = Nan::To<Boolean>(info[1]).ToLocalChecked()->Value();
	
	int events = (pause_recv ? 0 : UV_READABLE)
			| (pause_send ? 0 : UV_WRITABLE);

	if (! socket->deconstructing_ && socket->poll_initialised_) {
		if (events)
			uv_poll_start (socket->poll_watcher_, events, IoEvent);
		else 
			uv_poll_stop (socket->poll_watcher_);
	}
	
	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SocketWrap::Recv) {
	Nan::HandleScope scope;
	
	SocketWrap* socket = SocketWrap::Unwrap<SocketWrap> (info.This ());
	v8::Isolate* isolate = v8::Isolate::GetCurrent();
  	v8::Local<v8::Context> context = isolate->GetCurrentContext();
	Local<Object> buffer;
	sockaddr_storage sin_storage;
	char addr[50];
	int rc;
#ifdef _WIN32
	int sin_length = 0;
#else
	socklen_t sin_length = 0;
#endif

	if (socket->family_ == AF_INET6) {
		sin_length = sizeof (sockaddr_in6);
	} else if (socket->family_ == AF_INET) {
		sin_length = sizeof (sockaddr_in);
	} else {
		sin_length = sizeof(sockaddr_ll);
	}
	
	if (info.Length () < 2) {
		Nan::ThrowError("Two arguments are required");
		return;
	}
	
	if (! node::Buffer::HasInstance (info[0])) {
		Nan::ThrowTypeError("Buffer argument must be a node Buffer object");
		return;
	} else {
		buffer = Nan::To<Object>(info[0]).ToLocalChecked();
	}

	if (! info[1]->IsFunction ()) {
		Nan::ThrowTypeError("Callback argument must be a function");
		return;
	}

	rc = socket->CreateSocket ();
	if (rc != 0) {
		Nan::ThrowError(node::ErrnoException(isolate, errno, "createsocket"));
		return;
	}

	Local<Value> argv[2];
	Local<Function> cb = Local<Function>::Cast (info[1]);
	do {
		//memset (&sin_storage, 0, sin_length);
		rc = recvfrom (socket->poll_fd_, node::Buffer::Data (buffer),
				(int) node::Buffer::Length (buffer), 0, (sockaddr *) &sin_storage,
				&sin_length);
		
		if (rc == SOCKET_ERROR) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				argv[0] = Nan::New<Number>(-1);
				Nan::Call(Nan::Callback(cb), 1, argv);
				break;
			}
			Nan::ThrowError(node::ErrnoException(isolate, SOCKET_ERRNO, "recvfrom"));
			return;
		}
		
		if (socket->family_ == AF_INET6)
			uv_ip6_name ((sockaddr_in6*)&sin_storage, addr, 50);
		else if(socket->family_ == AF_INET)
			uv_ip4_name ((sockaddr_in*)&sin_storage, addr, 50);
		else
			addr[0] = 0; /* TODO */
			
		argv[0] = Nan::New<Number>(rc);
		argv[1] = Nan::New(addr).ToLocalChecked();
		MaybeLocal<v8::Value> newBuffer = cb->Call (context, socket->handle(), 2, argv);
		if(!newBuffer.ToLocal(&argv[0]) || !argv[0]->IsObject() || !node::Buffer::HasInstance(argv[0])) {
			break;
		}
		buffer = argv[0]->ToObject(context).ToLocalChecked();
	} while(true);
	
	info.GetReturnValue().Set(info.This());
}

static int find_and_set_index(int socket, const char * name, unsigned char* dest)
{
    struct ifreq ifreq;
	int index;

    memset(&ifreq, 0, sizeof ifreq);

    snprintf(ifreq.ifr_name, sizeof ifreq.ifr_name, "%s", name);

    if (ioctl(socket, SIOCGIFINDEX, &ifreq)) {
        return -1;
    }
	index = ifreq.ifr_ifindex;

    if (ioctl(socket, SIOCGIFHWADDR, &ifreq)) {
        return -2;
    }
	if (ifreq.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
		return -3; /* Not ethernet */
	}

	memcpy(dest, ifreq.ifr_hwaddr.sa_data, 8);

    return index;
}

NAN_METHOD(SocketWrap::Send) {
	Nan::HandleScope scope;
	
	SocketWrap* socket = SocketWrap::Unwrap<SocketWrap> (info.This ());
	v8::Isolate* isolate = v8::Isolate::GetCurrent();
  	v8::Local<v8::Context> context = isolate->GetCurrentContext();
	Local<Object> buffer;
	uint32_t offset;
	uint32_t length;
	int rc;
	char *data;
	bool try_send;
	
	if (info.Length () < 6) {
		Nan::ThrowError("Six arguments are required");
		return;
	}
	
	if (! node::Buffer::HasInstance (info[0])) {
		Nan::ThrowTypeError("Buffer argument must be a node Buffer object");
		return;
	}
	
	if (! info[1]->IsUint32 ()) {
		Nan::ThrowTypeError("Offset argument must be an unsigned integer");
		return;
	}

	if (! info[2]->IsUint32 ()) {
		Nan::ThrowTypeError("Length argument must be an unsigned integer");
		return;
	}
	
	if (! info[4]->IsFunction ()) {
		Nan::ThrowTypeError("Callback argument must be a function");
		return;
	}
	
	if (! info[5]->IsBoolean ()) {
		Nan::ThrowTypeError("Try argument must be a boolean");
		return;
	}

	rc = socket->CreateSocket ();
	if (rc != 0) {
		Nan::ThrowError(raw_strerror (errno));
		return;
	}
	
	buffer = Nan::To<Object>(info[0]).ToLocalChecked();
	offset = Nan::To<Uint32>(info[1]).ToLocalChecked()->Value();
	length = Nan::To<Uint32>(info[2]).ToLocalChecked()->Value();
	try_send = info[5]->ToBoolean (isolate)->Value ();

	data = node::Buffer::Data (buffer) + offset;
	
	if (socket->family_ == AF_INET6) {
		if (! info[3]->IsString ()) {
			Nan::ThrowTypeError("IPv6 Address argument must be a string");
			return;
		}

#if UV_VERSION_MAJOR > 0
		struct sockaddr_in6 addr;

		uv_ip6_addr(*Nan::Utf8String(info[3]), 0, &addr);
#else
		String::Utf8String address (args[3]);
		struct sockaddr_in6 addr = uv_ip6_addr (*address, 0);
#endif
		
		rc = sendto (socket->poll_fd_, data, length, 0,
				(struct sockaddr *) &addr, sizeof (addr));
	} else if (socket->family_ == AF_INET) {
		if (! info[3]->IsString ()) {
			Nan::ThrowTypeError("IPv4 Address argument must be a string");
			return;
		}
		
#if UV_VERSION_MAJOR > 0
		struct sockaddr_in addr;
		uv_ip4_addr(*Nan::Utf8String(info[3]), 0, &addr);
#else
		String::Utf8String address (info[3]);
		struct sockaddr_in addr = uv_ip4_addr (*address, 0);
#endif

		rc = sendto (socket->poll_fd_, data, length, 0,
				(struct sockaddr *) &addr, sizeof (addr));
	} else if (socket->family_ == PF_PACKET) {
		if (! info[3]->IsString ()) {
			Nan::ThrowTypeError("Interface Address argument must be a string");
			return;
		}

		struct sockaddr_ll addr;
		Nan::Utf8String address (info[3]);
		int ifindex = find_and_set_index(socket->poll_fd_, *address, addr.sll_addr);
		if (ifindex < 0){
			if(ifindex == -1){
				Nan::ThrowError("Unknown interface ID.");
			} else if(ifindex == -2){
				Nan::ThrowError("Unknown interface MAC.");
			} else if(ifindex == -2){
				Nan::ThrowError("Interface not Ethernet.");
			}
			return;
		}
		addr.sll_family = AF_PACKET;
		addr.sll_protocol = htons(ETH_P_ALL);
		addr.sll_ifindex = ifindex;
		addr.sll_hatype = htons(ARPHRD_ETHER);
		addr.sll_pkttype = PACKET_OUTGOING;
		addr.sll_halen = 8;

		rc = sendto (socket->poll_fd_, data, length, 0,
				(struct sockaddr *) &addr, sizeof (addr));
	} else {
		rc = ::send(socket->poll_fd_, data, length, 0);
	}
	
	if (rc == SOCKET_ERROR) {
		if(try_send && (errno == EAGAIN || errno == EWOULDBLOCK)){
			info.GetReturnValue().Set(Nan::New<Boolean>(false));
			return;	
		}
		Nan::ThrowError(node::ErrnoException(isolate, SOCKET_ERRNO, "send"));
		return;
	}
	
	Local<Function> cb = Local<Function>::Cast (info[4]);
	const unsigned argc = 1;
	Local<Value> argv[argc];
	argv[0] = Nan::New<Number>(rc);
	Nan::Call(Nan::Callback(cb), argc, argv);
	
	info.GetReturnValue().Set(info.This());
}

NAN_METHOD(SocketWrap::SetOption) {
	Nan::HandleScope scope;
	
	SocketWrap* socket = SocketWrap::Unwrap<SocketWrap> (info.This ());
	v8::Isolate* isolate = v8::Isolate::GetCurrent();
  	v8::Local<v8::Context> context = isolate->GetCurrentContext();
	
	if (info.Length () < 3) {
		Nan::ThrowError("Three or four arguments are required");
		return;
	}

	if (! info[0]->IsNumber ()) {
		Nan::ThrowTypeError("Level argument must be a number");
		return;
	}

	if (! info[1]->IsNumber ()) {
		Nan::ThrowTypeError("Option argument must be a number");
		return;
	}

	int level = Nan::To<Uint32>(info[0]).ToLocalChecked()->Value();
	int option = Nan::To<Uint32>(info[1]).ToLocalChecked()->Value();
	SOCKET_OPT_TYPE val = NULL;
	unsigned int ival = 0;
	SOCKET_LEN_TYPE len;

	if (info.Length () > 3) {
		if (! node::Buffer::HasInstance (info[2])) {
			Nan::ThrowTypeError("Value argument must be a node Buffer object if length is provided");
			return;
		}
		
		Local<Object> buffer = Nan::To<Object>(info[2]).ToLocalChecked();
		val = node::Buffer::Data (buffer);

		if (! info[3]->IsInt32 ()) {
			Nan::ThrowTypeError("Length argument must be an unsigned integer");
			return;
		}

		len = Nan::To<Uint32>(info[3]).ToLocalChecked()->Value();

		if (len > node::Buffer::Length (buffer)) {
			Nan::ThrowTypeError("Length argument is larger than buffer length");
			return;
		}
	} else {
		if (! info[2]->IsUint32 ()) {
			Nan::ThrowTypeError("Value argument must be a unsigned integer");
			return;
		}

		ival = Nan::To<Uint32>(info[2]).ToLocalChecked()->Value();
		len = 4;
	}

	int rc = setsockopt (socket->poll_fd_, level, option,
			(val ? val : (SOCKET_OPT_TYPE) &ival), len);

	if (rc == SOCKET_ERROR) {
		Nan::ThrowError(node::ErrnoException(isolate, SOCKET_ERRNO, "setsockopt"));
		return;
	}
	
	info.GetReturnValue().Set(info.This());
}

static int devIdFor(int _socket, const int *pDevId, bool isUp)
{
  int devId = 0; // default

  if (pDevId == nullptr)
  {
    struct hci_dev_list_req *dl;
    struct hci_dev_req *dr;

    dl = (hci_dev_list_req *)calloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl), 1);
    dr = dl->dev_req;

    dl->dev_num = HCI_MAX_DEV;

    if (ioctl(_socket, HCIGETDEVLIST, dl) > -1)
    {
      for (int i = 0; i < dl->dev_num; i++, dr++)
      {
        bool devUp = dr->dev_opt & (1 << HCI_UP);
        bool match = (isUp == devUp);

        if (match)
        {
          // choose the first device that is match
          // later on, it would be good to also HCIGETDEVINFO and check the HCI_RAW flag
          devId = dr->dev_id;
          break;
        }
      }
    }

    free(dl);
  }
  else
  {
    devId = *pDevId;
  }

  return devId;
}


NAN_METHOD(SocketWrap::BindBluetooth)
{
	Nan::HandleScope scope;

	struct sockaddr_hci a = {};
	SocketWrap* socket = SocketWrap::Unwrap<SocketWrap> (info.This ());

	int devId = 0;
	int* pDevId = nullptr;

	if (info.Length() > 0)
	{
		Local<Value> arg0 = info[0];
		if (arg0->IsInt32() || arg0->IsUint32())
		{
			devId = Nan::To<int32_t>(arg0).FromJust();
			pDevId = &devId;
		}
	}

	a.hci_family = AF_BLUETOOTH;
	a.hci_dev = devIdFor(socket->poll_fd_, pDevId, true);
	a.hci_channel = HCI_CHANNEL_USER;

	if (bind(socket->poll_fd_, (struct sockaddr *)&a, sizeof(a)) < 0)
	{
		Nan::ThrowError(Nan::ErrnoException(errno, "bind"));
		devId = -1;
	}

	info.GetReturnValue().Set(devId);
}

static void IoEvent (uv_poll_t* watcher, int status, int revents) {
	SocketWrap *socket = static_cast<SocketWrap*>(watcher->data);
	socket->HandleIOEvent (status, revents);
}

}; /* namespace raw */

#endif /* RAW_CC */
