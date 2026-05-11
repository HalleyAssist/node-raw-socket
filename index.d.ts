import { EventEmitter } from "events";

declare namespace raw {
	interface SocketOptions {
		addressFamily?: number;
		protocol?: number;
		bufferSize?: number;
		generateChecksums?: boolean;
		checksumOffset?: number;
		hciDevice?: number;
		netlinkPort?: number;
		netlinkGroup?: number;
	}

	interface ChecksumBuffer {
		buffer: Buffer;
		offset: number;
		length: number;
	}

	type ChecksumInput = Buffer | ChecksumBuffer;
	type BeforeSendCallback = (this: Socket) => void;
	type SendCallback = (this: Socket, error: Error | null, bytes: number) => void;
	type EventListener = (...args: any[]) => void;

	interface SocketLevelConstants {
		[key: string]: number | undefined;
		readonly SOL_SOCKET: number;
		readonly IPPROTO_IP: number;
		readonly IPPROTO_IPV6: number;
		readonly TCP_KEEPCNT: number;
	}

	interface SocketOptionConstants {
		[key: string]: number | undefined;
		readonly SO_BROADCAST: number;
		readonly SO_RCVBUF: number;
		readonly SO_RCVTIMEO: number;
		readonly SO_SNDBUF: number;
		readonly SO_SNDTIMEO: number;
		readonly IP_HDRINCL: number;
		readonly IP_OPTIONS: number;
		readonly IP_TOS: number;
		readonly IP_TTL: number;
		readonly IPV6_TTL: number;
		readonly IPV6_UNICAST_HOPS: number;
		readonly IPV6_V6ONLY: number;
		readonly IPV6_HDRINCL?: number;
		readonly SO_BINDTODEVICE?: number;
		readonly IP_MTU_DISCOVER?: number;
		readonly IP_PMTUDISC_DO?: number;
		readonly IP_PMTUDISC_DONT?: number;
	}

	interface SocketProtocolConstants {
		[key: string]: number | undefined;
		readonly None: number;
		readonly ICMP: number;
		readonly TCP: number;
		readonly UDP: number;
		readonly ICMPv6: number;
		readonly BTPROTO_HCI: number;
		readonly BTPROTO_L2CAP: number;
	}

	interface AddressFamilyConstants {
		[key: string]: number | undefined;
		readonly AF_INET: number;
		readonly AF_INET6: number;
		readonly PF_PACKET: number;
		readonly AF_BLUETOOTH: number;
		readonly AF_NETLINK: number;
		readonly IPv4: number;
		readonly IPv6: number;
		readonly Raw: number;
	}

	class Socket extends EventEmitter {
		constructor(options?: SocketOptions);

		readonly buffer: Buffer;
		options: SocketOptions;
		recvPaused: boolean;
		sendPaused: boolean;
		maxRecvPackets: number;

		close(): this;
		getOption(level: number, option: number, value: Buffer, length: number): number;
		pauseRecv(): this;
		pauseSend(): this;
		resumeRecv(): this;
		resumeSend(): this;
		pause(recv: boolean, send: boolean): this;
		send(buffer: Buffer, offset: number, length: number, address: string, afterCallback: SendCallback): this;
		send(buffer: Buffer, offset: number, length: number, address: string, beforeCallback: BeforeSendCallback | null | undefined, afterCallback: SendCallback): this;
		setOption(level: number, option: number, value: number): void;
		setOption(level: number, option: number, value: Buffer, length: number): void;

		on(event: "close", listener: () => void): this;
		on(event: "error", listener: (error: Error, buffer?: Buffer) => void): this;
		on(event: "message", listener: (buffer: Buffer, source: string, backingBuffer: Buffer) => void): this;
		on(event: "return", listener: (buffer: Buffer) => void): this;
		on(event: string, listener: EventListener): this;

		once(event: "close", listener: () => void): this;
		once(event: "error", listener: (error: Error, buffer?: Buffer) => void): this;
		once(event: "message", listener: (buffer: Buffer, source: string, backingBuffer: Buffer) => void): this;
		once(event: "return", listener: (buffer: Buffer) => void): this;
		once(event: string, listener: EventListener): this;

		addListener(event: "close", listener: () => void): this;
		addListener(event: "error", listener: (error: Error, buffer?: Buffer) => void): this;
		addListener(event: "message", listener: (buffer: Buffer, source: string, backingBuffer: Buffer) => void): this;
		addListener(event: "return", listener: (buffer: Buffer) => void): this;
		addListener(event: string, listener: EventListener): this;
	}

	function createChecksum(...buffers: ChecksumInput[]): number;
	function writeChecksum(buffer: Buffer, offset: number, checksum: number): Buffer;
	function createSocket(options?: SocketOptions): Socket;
	function htonl(uint32: number): number;
	function htons(uint16: number): number;
	function ntohl(uint32: number): number;
	function ntohs(uint16: number): number;

	const SocketLevel: SocketLevelConstants;
	const SocketOption: SocketOptionConstants;
	const SocketProtocol: SocketProtocolConstants;
	const Protocol: SocketProtocolConstants;
	const AddressFamily: AddressFamilyConstants;
}

declare const raw: {
	createChecksum: typeof raw.createChecksum;
	writeChecksum: typeof raw.writeChecksum;
	createSocket: typeof raw.createSocket;
	Socket: typeof raw.Socket;
	SocketLevel: raw.SocketLevelConstants;
	SocketOption: raw.SocketOptionConstants;
	SocketProtocol: raw.SocketProtocolConstants;
	Protocol: raw.SocketProtocolConstants;
	AddressFamily: raw.AddressFamilyConstants;
	htonl: typeof raw.htonl;
	htons: typeof raw.htons;
	ntohl: typeof raw.ntohl;
	ntohs: typeof raw.ntohs;
};

export = raw;