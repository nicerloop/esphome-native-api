const events = require('events');
const Promise = require('bluebird');
const Mdns = require('multicast-dns');

function parseEsphomePacket(packet, rinfo) {
    if (!packet.answers) return null;
    const ptr = packet.answers.find(({ type, name }) => type === 'PTR' && name === '_esphomelib._tcp.local');
    if (!ptr) return null;

    return {
        address: rinfo.address,
        family: rinfo.family
    }
}

class EsphomeDiscovery extends events {
    constructor (options = {}) {
        super();
        this._handleResponse = this._handleResponse.bind(this);
        this.options = options;
    }
    run() {
        this.mdns = Mdns(this.options);
        this.mdns.on('response', this._handleResponse);
        this.mdns.query({
            questions:[{
                name: '_esphomelib._tcp.local',
                type: 'PTR'
            }]
        });
    }

    close() {
        this.mdns.off('response', this._handleResponse);
        delete this.mdns;
    }
    
    _handleResponse(packet, rinfo) {
        const info = parseEsphomePacket(packet, rinfo);
        if (info) this.emit('info', info);
    }
}


module.exports = new Proxy(EsphomeDiscovery, {
    async apply (target, thisArg, [ { timeout = 5, ...options } = {} ]) {
        const discovery = new target(options);
        const hash = [];
        discovery.on('info', info => hash[info.address] = info);
        discovery.run();
        await Promise.delay(timeout * 1000);
        discovery.close();
        return Object.values(hash);
    }
});
