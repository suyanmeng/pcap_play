class Progress:
    def __init__(self, total_loop) -> None:
        self.total_loop = total_loop
        self.count = 0
        print(' ' * 20, end='\r')
    
    def show(self) -> None:
        self.count += 1
        print(self.count, '/', self.total_loop, end='\r')