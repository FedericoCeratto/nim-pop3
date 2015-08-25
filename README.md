### nim-pop3

Nim POP3 client library

Usage:

``` nim
import pop3
import logging
import net  # used for .Port

newConsoleLogger().addHandler()

let c = newPOP3Client(host="<pop_server_fqdn>")

c.user("<username>")
c.pass("<password>")
c.noop()  # do nothing

# list messages
echo c.list()

# list one message
echo c.list(msg_num=1)

# fetch message
echo c.retr(msg_num=1).body

# list message IDs
echo c.list_uidl()

# fetch statistics
echo c.stat()

# fetch capabilities
let caps = c.capa()

c.rset()
c.quit()
```

