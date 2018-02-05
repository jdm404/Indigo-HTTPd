# IFTTT

**2018-01-05:** *Not even sure if I should continue on my fork; the original has been updated and does quite a bit more than it once did. I need to re-examine my motivations and see if what I'm doing is even worth it.*

Much tighter integration with IFTTT web hooks than the basic HTTP methods. Spawns a private web server instance for now, hopefully will be able add SSL support using Lets Encrypt. 

Preliminary is working now, but it's not what I'd like (it just updates variables), and there's no docs. Much more work needed before this is useful for anyone other than me.

Would eventually like to hook into the IFTTT API to allow applet creation from Indigo with much of the annoying crap (URL, parameters, HTTP type, etc) pre-filled. https://platform.ifttt.com/docs/embedding_applets#embedding-applets
