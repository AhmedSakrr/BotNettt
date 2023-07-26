all: server bot

server: server.c
	gcc server.c -o server -lpthread
bot: bot.c
	gcc  bot.c  -o bot -lpthread
