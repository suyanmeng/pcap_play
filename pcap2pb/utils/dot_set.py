class DotSet:
    def __init__(self) -> None:
        self._dots = {}
    
    def add(self, x, y, id) -> None:
        if x not in self._dots:
            self._dots[x] = {y: id}
        else:
            self._dots[x][y] = id

    def find(self, x, y):
        if x not in self._dots or y not in self._dots[x]:
            return None
        return self._dots[x][y]