


nfrag: nfrag.c
	$(CC) $^ -o $@ -lnetfilter_queue

start: nfrag
	iptables -A OUTPUT -j NFQUEUE --queue-num 0 && ./nfrag

stop:
	iptables -F OUTPUT
