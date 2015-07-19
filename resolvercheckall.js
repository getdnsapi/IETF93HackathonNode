

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

/* Output codes
 *     V  answer verified ==? algorithm supported
 *     -  unverified answer
 *     x  Unspecified algorithm/digest/negative answer combination
 *     T  Timeout
 *     S  ServFail
 *     O  Other
 */

var maxAlg = 10
var maxDs = 8

var algs = [ "alg-1", "alg-3", "alg-5", "alg-6", "alg-7", "alg-8",
        "alg-10", "alg-12", "alg-13", "alg-14"] 
var names =  [ "RSA-MD5 OBSOLETE", "DSA/SHA1", "RSA/SHA1", "RSA-NSEC3-SHA1",
        "DSA-NSEC3-SHA1", "RSA-SHA256", "RSA-SHA512", "GOST-ECC", "ECDSAP256SHA256",
        "ECDSAP384SHA384" ]

// List the define DS digiest alogrithms As of 2014/11
var ds = [ "ds-1", "ds-2", "ds-3", "ds-4" ]

var number = [ 0, -1, 1, -1, 2, 3, 4, 5. -1, 6, -1, 7, 8, 9]
//var number = [ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" ]

//var result[][] // Results are stored in here
var zone = "dnssec-test.org."  // Our test zone anchors

var result;

results = new Array(10)
for (i=0; i < 10; i++)
{
    results[i]=new Array(8)
    for (j=0; j < 8; j++)
      results[i][j] = "S"
}

var res1 = "";
var resheader = "";
var restable = "";

var options = {
    // request timeout time in millis
    timeout : 5000,
    // upstream recursive servers
    upstreams : [
    "8.8.8.8"
    ],
    // always return dnssec status
    return_dnssec_status : true,
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


// getdns query callback
var callback = function(err, result) {
        

    process.stdout.write("In callback " + err + ":" + result + "\n");
    if (err != null) process.stdout.write("Error = " + JSON.stringify(err));
    // if not null, err is an object w/ msg and code.
    // code maps to a GETDNS_CALLBACK_TYPE
    // result is a response dictionary
     if (result == null ) {
        //g res1 += "<p>No result</p>";
        process.stdout.write("no result\n");
    } else {
        //g  res1 += "<tr>";
          for ( var index in result.replies_tree) {
            process.stdout.write("question = " +  JSON.stringify(result.replies_tree[index].question.qname, 0 , 2));
            process.stdout.write("question col = " +  JSON.stringify(result.replies_tree[index].question.qname.substr(3, 1), 0 , 2));
            process.stdout.write("question row = " +  JSON.stringify(result.replies_tree[index].question.qname.substr(9, 1), 0 , 2));
            process.stdout.write("status = " +  JSON.stringify(result.replies_tree[index].dnssec_status, 0, 2));
            var col = result.replies_tree[index].question.qname.substr(3, 1) - 1;
            var row = result.replies_tree[index].question.qname.substr(9, 1) - 1;
            process.stdout.write("row col " + row + " + " + col);
            if(result.replies_tree[index].question.qname.indexOf("nsec3") != -1) {
                col += 4;
                process.stdout.write("incremented col \n");
            }
            if (number[row] == -1) continue;
            if (result.replies_tree[index].header.ad == 1) 
            {
              process.stdout.write("row col " +  number[row] + " + " + row + " + "+ col);
              results[number[row]][col]= "V";
            }

            if (result.replies_tree[index].dnssec_status == getdns.DNSSEC_SECURE)
            {
            }
            else if (result.replies_tree[index].dnssec_status == getdns.DNSSEC_INSECURE)
            {
                results[number[row]][col]= "X";
            }
            else if (result.replies_tree[index].dnssec_status == getdns.GETDNS_DNSSEC_BOGUS)
            {
                results[number[row]][col]= "S";
            }
            else if (result.replies_tree[index].dnssec_status == getdns.GETDNS_DNSSEC_INDERERMINATE)
            {
                results[row][number[col]]= "O";
            }
            else if (result.replies_tree[index].dnssec_status == getdns.GETDNS_DNSSEC_NOT_PERFORMED)
            {
                results[row][number[col]]= "O";
            }
            else 
            { 
                results[row][number[col]]= "O";
            }  
    
            }
    }
    restable = "";
    for (i=0; i < 10; i++)
    {
      restable += "<tr>";
      restable += "<th>" + names[i] + "</th>";
      for (j=0; j < 8; j++)
        restable += "<td>" + results[i][j] + "</td>";
      restable += "</tr>";
    }
    var res2 = resheader + restable;
    process.stdout.write("\nresult = " + restable + "\n");
    app.get('/', function(req, res){
        res.send(res2);
    });
    // when done with a context, it must be explicitly destroyed
//    context.destroy();
}


    resolver = process.argv.slice(2);
    process.stdout.write("resolver = " + process.argv.slice(2) + "\n");

//  create the context with the above options
    var context = getdns.createContext(options);
    context.upstream_recursive_servers = resolver;
    resheader = "<h1>Responses for resolver " + resolver + "</h1>";
    resheader += "<h2>Queries and responses below: </h2>";
    resheader += "<p>NOTE: This web page is created using nodejs, the getdns API, in the expressjs framework. Source code will be available in github/getdnsapi/checkresolvers.</p>";

    resheader += "<table> <col width=\"10\"> <col width=\"10\"> <col width=\"10\"><col width=\"10\"><tr><th>Results</th><th>DS1_NSEC</th><th>DS2_NSEC</th><th>DS3_NSEC</th><th>DS4_NSEC</th> ";
    resheader += "<th>DS1_NSEC3</th><th>DS2_NSEC3</th><th>DS3_NSEC3</th><th>DS4_NSEC3</th> </tr>";

    resheader += "<p>Legend: V == Validates  - == Answer  x == Alg Not specified T == Timeout S == ServFail O == Other Error DS.</p> ";
    resheader += "<p>algs 1=SHA1 2=SHA2-256 3=GOST 4=SHA2-384</p>";
/*
    for (i=0; i < 10; i++)
    {
      restable += "<tr>";
      restable += "<th>" + names[i] + "</th>";
      for (j=0; j < 8; j++)
        restable += "<td>" + results[j][i] + "</td>";
      restable += "</tr>";
    }

    res1 = resheader + restable;
*/
    for (var i = 0; i < ds.length; i++)
    {
      for (j = 0; j < algs.length; j++)
      {
       process.stdout.write("name = " + ds[i]+ "." + algs[j] + "-nsec." + zone); 
       context.lookup(ds[i]+ "." + algs[j] + "-nsec." + zone, getdns.RRTYPE_TXT, callback);
//g       process.stdout.write("name = " + ds[i]+ "." + algs[j] + "-nsec3." + zone); 
//g       context.lookup(ds[i]+ "." + algs[j] + "-nsec3." + zone, getdns.RRTYPE_TXT, callback);
     }
   }
/*
    if (restable != "")
    {
      var res2 = resheader + restable;
      process.stdout.write("resultend = " + res2 + "\n");
      app.get('/', function(req, res){
        res.send(res2);
      });
    }
*/

if (!module.parent) {
  app.listen(50000);
  console.log('Express started on port 50000');
}
