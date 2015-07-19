

// Sample to demonstrate the usage of getdns nodejs API and host it
// in an express web context.
// Install from http://expressjs.com/ and follow instructions to setup in the Readme
//
//
// Replace the relative paths with your own path for the install of expressjs
var express = require('express');
var app = module.exports = express();

// You need getdns and getdns node installed prior to running this sample
// You can install this sample in the root directory of the getdnsnode install directory
// getdns includes. set LD_LIBRARY_PATH to /usr/local/lib
var getdns = require('getdns');

var resolver = "8.8.8.8"

var res1 = "";

var options = {
    // request timeout time in millis
    timeout : 5000,
    // upstream recursive servers
    upstreams : [
    "8.8.8.8"
    ],
    // always return dnssec status
//    return_dnssec_status : true,
//    dnssec_return_only_secure : true,
    dnssec_return_validation_chain : true
    };

var repl = function(key, value){
    if(key == "rdata_raw") { 
        return undefined;
    }
    if(key == "signature"){
        return undefined;
    }
    if(key == "certificate_association_data"){
        return undefined;
    }
    return value;
};

/**
*
*  Base64 encode / decode
*  http://www.webtoolkit.info/
*
**/
var Base64 = {

// private property
_keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

// public method for encoding
encode : function (input) {
    var output = "";
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var i = 0;
    if (!input) return "";
    //input = Base64._utf8_encode(input);

    while (i < input.length) {

        chr1 = input[i++];
        chr2 = input[i++];
        chr3 = input[i++];

        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;

        if (isNaN(chr2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
            enc4 = 64;
        }

        output = output +
        this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) +
        this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);

    }

    return output;
},

}

var sleep = function (milliseconds) {
  var start = new Date().getTime();
  for (var i = 0; i < 1e7; i++) {
    if ((new Date().getTime() - start) > milliseconds){
      break;
    }
  }
}

// getdns query callback
var callback = function(err, result) {
        
    process.stdout.write("In callback " + err + ":" + result.status + "\n");
    if (err != null) process.stdout.write("Error = " + JSON.stringify(err));
    // if not null, err is an object w/ msg and code.
    // code maps to a GETDNS_CALLBACK_TYPE
    // result is a response dictionary
     if (result == null ) {
        //g res1 += "<p>No result</p>";
        process.stdout.write("no result\n");
    } else {
          res1 += "<tr>";
          for ( var index in result.replies_tree) {
            process.stdout.write("question = " +  JSON.stringify(result.replies_tree[index].question.qname, 0 , 2));
            process.stdout.write("header = " +  JSON.stringify(result.replies_tree[index].header, 0 , 2));
            process.stdout.write("status = " +  JSON.stringify(result.replies_tree[index].dnssec_status, 0, 2));
            res1 += "<td> " + JSON.stringify(result.replies_tree[index].question.qname, 0, 4) + "</td><td>";
            res1 +=  JSON.stringify(result.replies_tree[index].header.ad, 0 , 2) + "</td>"; 
            /*if (result.replies_tree[index].dnssec_status == getdns.DNSSEC_SECURE)
                res1 += "<td>GETDNS_DNSSEC_SECURE</td>";
            else if (result.replies_tree[index].dnssec_status == getdns.DNSSEC_INSECURE)
                res1 += "<td>GETDNS_DNSSEC_INSECURE</td>";
            else if (result.replies_tree[index].dnssec_status == getdns.GETDNS_DNSSEC_BOGUS)
                res1 += "<td>GETDNS_DNSSEC_BOGUS</td>";
            else if (result.replies_tree[index].dnssec_status == getdns.GETDNS_DNSSEC_INDERERMINATE)
                res1 += "<td>GETDNS_DNSSEC_INDETERMINATE</td>";
            else if (result.replies_tree[index].dnssec_status == getdns.GETDNS_DNSSEC_NOT_PERFORMED)
                res1 += "<td>GETDNS_DNSSEC_NOT_PERFORMED</td>";
            else res1 += "<td>NA</td>";
*/
            }
           res1 += "</tr>";
           

    }
    app.get('/', function(req, res){
        res.send(res1);
    });
    // when done with a context, it must be explicitly destroyed
//    context.destroy();
}


    resolver = process.argv.slice(2);
    process.stdout.write("resolver = " + process.argv.slice(2) + "\n");

//  create the context with the above options
    var context = getdns.createContext(options);
    context.upstream_recursive_servers = resolver;
    res1 = "<h1>Responses for resolver " + resolver + "</h1>";
    res1 += "<h2>Queries and responses below: </h2>";
    res1 += "<p>NOTE: This web page is created using nodejs, the getdns API, in the expressjs framework. Source code will be available in github/getdnsapi/checkresolvers.</p>";

    res1 += "<table> <col width=\"50\"> <col width=\"10\"> <col width=\"50\"><tr><th>Name</th><th>ad bit</th> </tr>";
    //res1 += "<table> <col width=\"50\"> <col width=\"10\"> <col width=\"50\"><tr><th>Name</th><th>ad bit</th><th>dnssec_return_status</th> </tr>";

// getdns general
// last argument must be a callback

   var transactionId5 = context.lookup("alg-8-nsec3.dnssec-test.org", getdns.RRTYPE_SOA, callback);
   var transactionId3 = context.lookup("doesnotexist.dnssec-test.org", getdns.RRTYPE_TXT, callback);
   var transactionId = context.lookup("alg-13-nsec.dnssec-test.org", getdns.RRTYPE_A, callback);
   var transactionId4 = context.lookup("dnssec-failed.org", getdns.RRTYPE_SOA, callback);
//    res1 += "</table>";

    app.get('/', function(req, res){
        res.send(res1);
    });


if (!module.parent) {
  app.listen(50000);
  console.log('Express started on port 50000');
}
