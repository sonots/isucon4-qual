backend default {
  .host = "127.0.0.1";
  .port = "10080";
}

# import std; # ログ出力

sub vcl_recv {
   if (req.url ~ "^/stylesheets") {
       return(lookup); # use cache
   }
   if (req.url ~ "^/images") {
       return(lookup); # use cache
   }
   if (req.url == "/") {
       return(lookup); # use cache
   }
   if (req.url == "/?out=1") {
       return(lookup); # use cache
   }
   if (req.url == "/?out=2") {
       return(lookup); # use cache
   }
   if (req.url == "/?out=3") {
       return(lookup); # use cache
   }
   if (req.url == "/?out=4") {
       return(lookup); # use cache
   }
   else {
       return(pass); # pass to upstream
   }
}

sub vcl_fetch {
}

sub vcl_error {
    if((obj.status >= 100 && obj.status < 200) || obj.status == 204 || obj.status == 304){
        return (deliver);
    }
}
