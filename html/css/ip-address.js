/* Management-address validation and ordering shared by Inventory and Discover. */
(function (root) {
    'use strict';

    function ipv4(value) {
        const parts = value.split('.');
        if (parts.length !== 4 || parts.some(part => !/^(0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255)) return null;
        return parts.map(Number);
    }

    function parse(value, requireScope = true) {
        if (typeof value !== 'string') return null;
        const text = value.trim();
        if (!text || /\s/.test(text)) return null;
        const scoped = text.split('%');
        if (scoped.length > 2 || (scoped.length === 2 && !/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(scoped[1]))) return null;
        let literal = scoped[0];
        const scope = scoped[1] || '';
        if (!literal.includes(':')) {
            const octets = ipv4(literal);
            return octets && !scope ? { version: 4, words: octets, scope: '', canonical: octets.join('.') } : null;
        }
        if (literal.includes('.')) {
            const separator = literal.lastIndexOf(':');
            const octets = ipv4(literal.slice(separator + 1));
            if (!octets) return null;
            literal = literal.slice(0, separator + 1) + ((octets[0] << 8) + octets[1]).toString(16) + ':' + ((octets[2] << 8) + octets[3]).toString(16);
        }
        const halves = literal.split('::');
        if (halves.length > 2) return null;
        const left = halves[0] ? halves[0].split(':') : [];
        const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
        if ([...left, ...right].some(word => !/^[0-9a-f]{1,4}$/i.test(word))) return null;
        const omitted = 8 - left.length - right.length;
        if ((halves.length === 1 && omitted !== 0) || (halves.length === 2 && omitted < 1)) return null;
        const words = [...left.map(word => parseInt(word, 16)), ...Array(omitted).fill(0), ...right.map(word => parseInt(word, 16))];
        if (requireScope && (words[0] & 0xffc0) === 0xfe80 && !scope) return null;
        let canonical;
        if (words.slice(0, 5).every(word => word === 0) && words[5] === 0xffff) {
            canonical = '::ffff:' + [words[6] >> 8, words[6] & 255, words[7] >> 8, words[7] & 255].join('.');
        } else {
            let bestStart = -1, bestLength = 1;
            for (let index = 0; index < words.length;) {
                if (words[index] !== 0) { index++; continue; }
                const start = index;
                while (index < words.length && words[index] === 0) index++;
                if (index - start > bestLength) { bestStart = start; bestLength = index - start; }
            }
            const hex = words.map(word => word.toString(16));
            canonical = bestStart < 0 ? hex.join(':') : hex.slice(0, bestStart).join(':') + '::' + hex.slice(bestStart + bestLength).join(':');
        }
        return { version: 6, words, scope, canonical: canonical + (scope ? '%' + scope : '') };
    }

    function key(value) {
        return parse(value, false)?.canonical || String(value || '').trim();
    }

    function compare(left, right) {
        const a = parse(left, false), b = parse(right, false);
        if (!a || !b) return a ? 1 : b ? -1 : String(left || '').localeCompare(String(right || ''), undefined, { numeric: true });
        if (a.version !== b.version) return a.version - b.version;
        for (let index = 0; index < a.words.length; index++) {
            if (a.words[index] !== b.words[index]) return a.words[index] - b.words[index];
        }
        return a.scope.localeCompare(b.scope);
    }

    function isIPv6(value) {
        return parse(value, false)?.version === 6;
    }

    function numeric(address) {
        const width = address.version === 4 ? 8n : 16n;
        return address.words.reduce((total, word) => (total << width) + BigInt(word), 0n);
    }

    // Count before expansion. A /64 is rejected without allocating an address list.
    function discoveryError(value, limit = 1500) {
        if (!String(value || '').trim()) return '';
        let count = 0n;
        for (const raw of String(value).split(',')) {
            const segment = raw.trim();
            if (!segment) continue;
            let first, last, start, end;
            if (segment.includes('/')) {
                const parts = segment.split('/');
                first = parse(parts[0]);
                if (parts.length !== 2 || !first || !/^\d+$/.test(parts[1])) return 'Invalid discovery address or CIDR. Link-local IPv6 requires %interface.';
                const prefix = Number(parts[1]);
                const bits = first.version === 4 ? 32 : 128;
                if (prefix > bits) return 'Invalid discovery CIDR prefix.';
                const hostBits = BigInt(bits - prefix);
                start = (numeric(first) >> hostBits) << hostBits;
                end = start + (1n << hostBits) - 1n;
                if (first.version === 4 && prefix < 31) { start++; end--; }
                if (first.version === 6 && prefix < 127) start++;
            } else if ((first = parse(segment))) {
                start = end = numeric(first);
            } else {
                for (let index = segment.indexOf('-'); index >= 0; index = segment.indexOf('-', index + 1)) {
                    first = parse(segment.slice(0, index));
                    last = parse(segment.slice(index + 1));
                    if (first && last && first.version === last.version && first.scope === last.scope) break;
                    first = last = null;
                }
                if (!first || !last) return 'Invalid discovery range. Use complete IPv4/IPv6 endpoints with matching %interface for link-local IPv6.';
                start = numeric(first); end = numeric(last);
            }
            if (end < start) return 'Discovery range end must not precede its start.';
            const multicastStart = first.version === 4 ? 0xe0000000n : (0xffn << 120n);
            const multicastEnd = first.version === 4 ? 0xefffffffn : ((1n << 128n) - 1n);
            if (start === 0n || (start <= multicastEnd && end >= multicastStart)) return 'Discovery requires unicast addresses; unspecified and multicast targets are not supported.';
            count += end - start + 1n;
            if (count > BigInt(limit)) return `Discovery is limited to ${limit.toLocaleString('en-US')} addresses. Use specific IPv6 addresses or smaller ranges.`;
        }
        return count ? '' : 'Enter a discovery address or range.';
    }

    root.LLDPqIP = { parse, key, compare, isIPv6, discoveryError };
})(globalThis);
