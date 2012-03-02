var connect = require('connect')
  , http = require('http');

var app = connect();
 app.use(connect.favicon());
 app.use(connect.logger());
 app.use(connect.static(__dirname + '/public'));

app.listen(3000);