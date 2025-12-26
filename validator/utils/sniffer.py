import time
from queue import Queue
from scapy.all import AsyncSniffer, sendp

class RXSniffer:
    def __init__(self, iface):
        self.iface = iface
        self.queue = Queue()
        self.sniffer = None

    def _handler(self, pkt):
        # Push every packet into the queue
        self.queue.put(pkt)

    def start(self):
        self.sniffer = AsyncSniffer(
            iface=self.iface,
            prn=self._handler,
            store=False
        )
        self.sniffer.start()
        time.sleep(0.5)  # Give some time to start
        
        
    def _flush(self):
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except:
                break

    def stop(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None

    import time

    def wait_for_reply(self, match_fn, timeout):
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                pkt = self.queue.get(timeout=0.05)
            except:
                continue

            if match_fn(pkt):
                return pkt

        return None
    
    def send_and_wait(self, pkt, match_fn, timeout=3.0):
        self._flush() #clear any stale entries 
        sendp(pkt, iface=self.iface, verbose=0)
        return self.wait_for_reply(match_fn, timeout)