# Slanger RCE

RCE in Slanger (a Ruby implementation of Pusher) using deserialization of Ruby objects ! 

> While researching a web application last February, I learned about Slanger, an open source server implementation of Pusher. In this post I describe the discovery of a critical RCE vulnerability in Slanger 0.6.0, and the efforts that followed to responsibly disclose the vulnerability.

![capture d'écran_1](https://user-images.githubusercontent.com/5891788/54571628-f64a9e80-49e3-11e9-8cdd-32229fdfd0c8.png)
found by [Pieter Hiele](https://twitter.com/honoki)

**Technical Analysis**:
- https://www.honoki.net/2019/03/rce-in-slanger-0-6-0/
- https://www.honoki.net/2019/03/rce-in-slanger-0-6-0/2/

**Patch**:
- https://github.com/stevegraham/slanger/commit/5267b455caeb2e055cccf0d2b6a22727c111f5c3

---

### Proof Of Concept

The Slanger application uses the ressource `Oj.load` to read the json sent by the user through the websocket channel. The json is not loaded with the secure option `Oj.strict_load()` as explained by the [Oj library](https://github.com/ohler55/oj/blob/master/pages/Security.md).

![image](https://user-images.githubusercontent.com/5891788/54572233-b802ae80-49e6-11e9-978f-ec01c515e93e.png)

https://github.com/stevegraham/slanger/blob/7fb5f439b45d8e128883b3e9e9d59dd2e8deb284/lib/slanger/handler.rb#L28

Therefore, the application is vulnerable to a remote code execution using unsecure ruby object deserialization.

1. To build the serialized object is use the [Rails 3.2.10 Remote Code Execution](https://github.com/charliesome/charlie.bz/blob/master/posts/rails-3.2.10-remote-code-execution.md) ressource 
2. Then send the payload though the websocket channel
3. That it.

### Exploit

```
python3 slanger-exploit.py
```

![image](https://user-images.githubusercontent.com/5891788/54571529-6573c300-49e3-11e9-97da-ffcad66604a1.png)


---

```diff
From 5267b455caeb2e055cccf0d2b6a22727c111f5c3 Mon Sep 17 00:00:00 2001
From: Pieter Hiele <pieter@honoki.net>
Date: Wed, 27 Feb 2019 10:15:22 +0100
Subject: [PATCH] bug fixes

---
 lib/slanger/api/request_validation.rb | 4 ++--
 lib/slanger/connection.rb             | 2 +-
 lib/slanger/handler.rb                | 4 ++--
 lib/slanger/presence_channel.rb       | 2 +-
 lib/slanger/redis.rb                  | 2 +-
 5 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/lib/slanger/api/request_validation.rb b/lib/slanger/api/request_validation.rb
index 1f2318a..56646ee 100644
--- a/lib/slanger/api/request_validation.rb
+++ b/lib/slanger/api/request_validation.rb
@@ -12,7 +12,7 @@ def initialize(*args)
       end
 
       def data
-        @data ||= Oj.load(body["data"] || params["data"])
+        @data ||= Oj.strict_load(body["data"] || params["data"])
       end
 
       def body
@@ -87,7 +87,7 @@ def parse_body!
       end
 
       def assert_valid_json!(string)
-        Oj.load(string)
+        Oj.strict_load(string)
       rescue Oj::ParserError
         raise Slanger::InvalidRequest.new("Invalid request body: #{raw_body}")
       end
diff --git a/lib/slanger/connection.rb b/lib/slanger/connection.rb
index 3a98d58..463b1e7 100644
--- a/lib/slanger/connection.rb
+++ b/lib/slanger/connection.rb
@@ -9,7 +9,7 @@ def initialize socket, socket_id=nil
     end
 
     def send_message m
-      msg = Oj.load m
+      msg = Oj.strict_load m
       s = msg.delete 'socket_id'
       socket.send Oj.dump(msg, mode: :compat) unless s == socket_id
     end
diff --git a/lib/slanger/handler.rb b/lib/slanger/handler.rb
index f294c34..2cd2d5a 100644
--- a/lib/slanger/handler.rb
+++ b/lib/slanger/handler.rb
@@ -25,9 +25,9 @@ def initialize(socket, handshake)
     # Dispatches message handling to method with same name as
     # the event name
     def onmessage(msg)
-      msg = Oj.load(msg)
+      msg = Oj.strict_load(msg)
 
-      msg['data'] = Oj.load(msg['data']) if msg['data'].is_a? String
+      msg['data'] = Oj.strict_load(msg['data']) if msg['data'].is_a? String
 
       event = msg['event'].gsub(/\Apusher:/, 'pusher_')
 
diff --git a/lib/slanger/presence_channel.rb b/lib/slanger/presence_channel.rb
index d996fa6..3600b92 100644
--- a/lib/slanger/presence_channel.rb
+++ b/lib/slanger/presence_channel.rb
@@ -32,7 +32,7 @@ def initialize(attrs)
     end
 
     def subscribe(msg, callback, &blk)
-      channel_data = Oj.load msg['data']['channel_data']
+      channel_data = Oj.strict_load msg['data']['channel_data']
       public_subscription_id = SecureRandom.uuid
 
       # Send event about the new subscription to the Redis slanger:connection_notification Channel.
diff --git a/lib/slanger/redis.rb b/lib/slanger/redis.rb
index b62345c..f79ac0e 100644
--- a/lib/slanger/redis.rb
+++ b/lib/slanger/redis.rb
@@ -25,7 +25,7 @@ def publisher
     def subscriber
       @subscriber ||= new_connection.pubsub.tap do |c|
         c.on(:message) do |channel, message|
-          message = Oj.load(message)
+          message = Oj.strict_load(message)
           c = Channel.from message['channel']
           c.dispatch message, channel
         end
```


