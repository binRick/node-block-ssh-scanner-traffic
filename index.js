var validateip = require('validate-ip'),
    async = require('async'),
    inSubnet = require('insubnet'),
    c = require('chalk'),
    parse = require('parse-spawn-args').parse,
    condenseWhitespace = require('condense-whitespace'),
    _ = require('underscore'),
    child = require('child_process'),
    fs = require('fs'),
    config = require('./config'),
    pmacctdProcess = null,
    pcapFilter = '',
    pmacctdProcess = null,
    dropCommand = '/sbin/iptables -I FORWARD -s _SRC_ -j DROP',
    Dropped = [],
    Attackers = {};



var nonLocalAddress = function(ip) {
    var nonLocal = true;
    _.each(config.localNetworks, function(net) {
        if (inSubnet.Auto(ip, net)) nonLocal = false;
    });
    return nonLocal;
};

setInterval(function(){
	Dropped = child.execSync('iptables -L FORWARD -n').toString().split('\n').filter(function(l){
return l.match(/^DROP*./g);
	}).map(function(l){
return condenseWhitespace(l);
	}).filter(function(l){
return l.split(' ').length==5 && validateip(l.split(' ')[3]) && l.split(' ')[1]=='all' && l.split(' ')[4]=='0.0.0.0/0';
	}).map(function(l){
return l.split(' ')[3];
	});
}, 2000);


setInterval(function() {
    _.each(_.keys(Attackers), function(attacker) {
        Attackers[attacker].Destinations = Attackers[attacker].Destinations.filter(function(d) {
            return d.Created > (Math.round(new Date().getTime() / 1000) - 120);
        });
        if (Attackers[attacker].Destinations.length == 0) {
            console.log('\t\t\t\t\tRemoving attacker ' + c.white(attacker));
            delete Attackers[attacker];
        }
    });
}, 10000);
setInterval(function() {
    console.log(c.green('Looking for scanners in ' + _.keys(Attackers).length + ' Attackers...'));
    _.each(_.keys(Attackers), function(attacker) {
        var dests = Attackers[attacker].Destinations.filter(function(D) {
            return D.Created > (Math.round(new Date().getTime() / 1000) - config.scannerIntervalSeconds);
        });
        console.log(c.green('\tAttacker ' + c.white(attacker) + ' has ' + c.white(Attackers[attacker].Destinations.length) + ' destinations and ' + c.white(dests.length) + ' within the last ' + c.white(config.scannerIntervalSeconds) + ' seconds'));
        if (dests.length >= config.scannerThreshold) {
            console.log(c.red('\t\tDropping src host ' + attacker + '!'));
            var dCmd = dropCommand.replace('_SRC_', attacker);
            console.log('\t\t\t' + dCmd);
	                delete Attackers[attacker];
            child.execSync(dCmd);
        }

    });
}, 5000);

var processTopTalkers = function(topTalkers) {
    topTalkers = condenseWhitespace(topTalkers).split('\n').filter(function(i) {
        return i.split(' ').length == 4 && validateip(i.split(' ')[0]) && validateip(i.split(' ')[1]);
    }).map(function(i) {
        return {
            src: i.split(' ')[0],
            dst: i.split(' ')[1],
        };
    }).filter(function(i) {
        return nonLocalAddress(i.src) && !_.contains(Dropped, i.src);
    });
    var updated = 0;
    _.each(topTalkers, function(tt) {
        if (!_.contains(_.keys(Attackers), tt.src)) {
            Attackers[tt.src] = {
                Destinations: [],
                Created: Math.round(new Date().getTime() / 1000),
                Updated: Math.round(new Date().getTime() / 1000),
            };
        }
        Attackers[tt.src].Destinations.push({
            dst: tt.dst,
            Created: Math.round(new Date().getTime() / 1000),
        });
        Attackers[tt.src].Updated = Math.round(new Date().getTime() / 1000);
    });
//    console.log(topTalkers.length + ' updates / ' + _.keys(Attackers).length, 'Attackers');
};

process.on('exit', function() {
    if (pmacctdProcess) {
        console.log(c.yellow('\nKilling pmacctd child process with pid ' + c.red.bgWhite(pmacctdProcess.pid)));
        pmacctdProcess.kill();
    }
});
_.each(config.localNetworks, function(net, index) {
    if (index > 0)
        pcapFilter += ' or ';
    pcapFilter += 'dst net ' + net;
});
var pmArgs = parse(String('-i ' + config.interface + ' -P print -r ' + config.interval + ' -c ' + 'src_host,dst_host') + ' \'' + pcapFilter + ' and dst port 22 and tcp[tcpflags] & (tcp-syn|tcp-ack) != 0\'');
pmacctdProcesses = child.spawn(config.pmacctd, pmArgs);
pmacctdProcesses.on('exit', function(code) {
    console.log('pmacctd exited with code', code);
});
pmacctdProcesses.stdout.on('data', function(data) {
    processTopTalkers(data.toString());
});
pmacctdProcesses.stderr.on('data', function(data) {});
