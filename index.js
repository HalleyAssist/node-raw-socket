
const {EventEmitter} = require ("events"),
	net = require ("net"),
	raw = require ("./build/Release/raw.node");

class Socket extends EventEmitter {
	constructor(options) {
		super()

		this.requests = [];

		this.recvPaused = false;
		this.sendPaused = true;
		this.bufferAlloc(options)

		const addressFamily = ((options && options.addressFamily === undefined)
			? exports.AddressFamily.IPv4
			: options.addressFamily)
		this.wrap = new raw.SocketWrap (
				((options && options.protocol)
						? options.protocol
						: 0),
				addressFamily
			);
		this.options = options


		switch(addressFamily) {
			case exports.AddressFamily.AF_BLUETOOTH:	
				this.wrap.bindBluetooth(options.hciDevice)
				break
			case exports.AddressFamily.AF_NETLINK:
				this.wrap.bindNetlink(options.netlinkPort || 0, options.netlinkGroup || 0);
				break
		}

		let me = this;
		this.wrap._sendReady = this.onSendReady.bind (me);
		this.wrap._recvReady = this.onRecvReady.bind (me);
		this.wrap._error = this.onError.bind (me);
		this.wrap._close = this.onClose.bind (me);

		this._gcFix = setInterval(()=>this.wrap, 2147483647).unref();

		this.maxRecvPackets = 1
	}

	emitSocketMessage(newBuffer, source, buffer) {
		this.emit ("message", newBuffer, source, buffer);
	}

	emitSocketReturn(buffer) {
		this.emit ("return", buffer);
	}

	emitSocketError(error, buffer = undefined) {
		this.emit ("error", error, buffer);
	}

	bufferAlloc(options){
		this._buffer = Buffer.alloc ((options && options.bufferSize !== undefined)
				? options.bufferSize
				: 4096);
	}

	get buffer(){
		return this._buffer
	}

	close () {
		this.wrap.close ();
		return this;
	}
	
	getOption (level, option, value, length) {
		return this.wrap.getOption (level, option, value, length);
	}
	
	onClose () {
		this.emit ("close");
		clearInterval(this._gcFix)
	}
	
	onError (error) {
		this.emitSocketError(error);
		this.close ();
	}
	
	onRecvReady () {
		let buffer = this.buffer
		try {
			let remaining = this.maxRecvPackets
			this.wrap.recv (buffer, (bytes, source)=>{
				if(bytes < 0) {
					this.emitSocketReturn (buffer);
					return
				}
				const newBuffer = buffer.slice (0, bytes);
				this.emitSocketMessage (newBuffer, source, buffer);
				if(this.recvPaused || --remaining == 0) {
					return
				}
				buffer = this.buffer
				return buffer
			})
		} catch (error) {
			this.emitSocketError(error, buffer);
		}
	}
	
	onSendReady () {
		if (this.requests.length > 0) {
			const me = this;
			const req = this.requests.shift ();
			try {
				if (req.beforeCallback)
					req.beforeCallback ();
				this.wrap.send (req.buffer, req.offset, req.length,
						req.address, function (bytes) {
					req.afterCallback.call (me, null, bytes);
				}, false);
			} catch (error) {
				req.afterCallback.call (me, error, 0);
			}
		} else {
			if (! this.sendPaused)
				this.pauseSend ();
		}
	}
	
	pauseRecv  () {
		this.recvPaused = true;
		this.wrap.pause (this.recvPaused, this.sendPaused);
		return this;
	}
	
	pauseSend () {
		this.sendPaused = true;
		this.wrap.pause (this.recvPaused, this.sendPaused);
		return this;
	}
	
	resumeRecv () {
		this.recvPaused = false;
		this.wrap.pause (this.recvPaused, this.sendPaused);
		return this;
	}
	
	resumeSend () {
		this.sendPaused = false;
		this.wrap.pause (this.recvPaused, this.sendPaused);
		return this;
	}

	pause (recv, send) {
		this.recvPaused = recv;
		this.sendPaused = send;
		this.wrap.pause (this.recvPaused, this.sendPaused);
		return this;
	}
	
	send (buffer, offset, length, address,
			beforeCallback, afterCallback) {
		if (! afterCallback) {
			afterCallback = beforeCallback;
			beforeCallback = null;
		}
	
		if (length + offset > buffer.length)  {
			afterCallback.call (this, new Error ("Buffer length '" + buffer.length
					+ "' is not large enough for the specified offset '" + offset
					+ "' plus length '" + length + "'"));
			return this;
		}
	
		if (
			(this.options.addressFamily == exports.AddressFamily.IPv4 || this.options.addressFamily == exports.AddressFamily.IPv6)
			&& ! net.isIP (address)) {
			afterCallback.call (this, new Error ("Invalid IP address '" + address + "'"));
			return this;
		}
	
		const req = { buffer, offset, length, address, afterCallback, beforeCallback };
	
		if (this.sendPaused) {
			if (req.beforeCallback)
				req.beforeCallback ();
			
			try {
				let sent = this.wrap.send (req.buffer, req.offset, req.length, req.address, (bytes) => {
					req.afterCallback.call (this, null, bytes);
				}, true);

				if (sent) {
					return this
				}
			} catch(error){
				req.afterCallback.call (this, error, 0);
				return
			}
			
			this.requests.push (req);

			this.resumeSend ();
		} else {		
			this.requests.push (req);
		}
	
		return this;
	}
	
	setOption (level, option, value, length) {
		if (arguments.length > 3)
			this.wrap.setOption (level, option, value, length);
		else
			this.wrap.setOption (level, option, value);
	}
}

exports.createChecksum = function () {
	let sum = 0;
	for (let i = 0; i < arguments.length; i++) {
		const object = arguments[i];
		if (object instanceof Buffer) {
			sum = raw.createChecksum (sum, object, 0, object.length);
		} else {
			sum = raw.createChecksum (sum, object.buffer, object.offset,
					object.length);
		}
	}
	return sum;
}

exports.writeChecksum = function (buffer, offset, checksum) {
	buffer.writeUInt8 ((checksum & 0xff00) >> 8, offset);
	buffer.writeUInt8 (checksum & 0xff, offset + 1);
	return buffer;
}

exports.createSocket = function (options) {
	return new Socket (options || {});
};

exports.Socket = Socket;

exports.SocketLevel = raw.SocketLevel;
exports.SocketOption = raw.SocketOption;
exports.SocketProtocol = exports.Protocol = raw.SocketProtocol;

const IpProtocols = {
	"None" : 0,
	"ICMP" : 1,
	"TCP" : 6,
	"UDP" : 17,
	"ICMPv6" : 58
}
Object.assign(exports.Protocol, IpProtocols)

exports.AddressFamily = raw.AddressFamily
exports.AddressFamily.Raw = exports.AddressFamily.PF_PACKET
exports.AddressFamily.IPv4 = exports.AddressFamily.AF_INET
exports.AddressFamily.IPv6 = exports.AddressFamily.AF_INET6

exports.htonl = raw.htonl;
exports.htons = raw.htons;
exports.ntohl = raw.ntohl;
exports.ntohs = raw.ntohs;
