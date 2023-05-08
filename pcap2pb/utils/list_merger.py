from cmath import rect
from sre_constants import SRE_FLAG_VERBOSE


class ListMerger:
    def __init__(self, body=[]) -> None:
        self._body = body
        self._fragments = []

    def add(self, fragment):
        if not self._merge(fragment):
            self._fragments.append(fragment)

    def _merge(self, fragment):
        body_len = len(self._body)
        if body_len == 0:
            self._body = fragment
            return True
        frg_len = len(fragment)
        if frg_len == 0:
            return True
        front_found = False
        front = []
        rear_found = False
        rear = []
        if self._body[0] in fragment:
            head = fragment.index(self._body[0])
            front_found = True
            len_items_2_compare = min(frg_len-1-head, body_len-1)
            for i in range(1, len_items_2_compare+1):
                if fragment[head+i] != self._body[i]:
                    front_found = False
                    break
            if front_found:
                front = fragment[:head]
        if self._body[-1] in fragment:
            tail = fragment.index(self._body[-1])
            rear_found = True
            len_items_2_compare = min(tail, body_len-1)
            for i in range(1, len_items_2_compare+1):
                if fragment[tail-i] != self._body[-1-i]:
                    rear_found = False
                    break
            if rear_found:
                rear = fragment[tail+1:]
        if not front_found and not rear_found:
            fragment_in_body = True
            for frg in fragment:
                if frg not in self._body:
                    fragment_in_body = False
                    break
            return fragment_in_body
        if front_found:
            self._body = front + self._body
        if rear_found:
            self._body = self._body + rear
        return True

    def result(self):
        fragments_changed = True
        while fragments_changed:
            fragments_changed = False
            for fragment in self._fragments:
                if self._merge(fragment):
                    self._fragments.remove(fragment)
                    fragments_changed = True
                    break
        ret = self._body
        for fragment in self._fragments:
            ret += fragment
        return ret


if __name__ == "__main__":
    l = ListMerger()
    l.add([2,3,4,5,6,7])
    l.add([9])
    l.add([1])
    l.add([8,9])
    l.add([8,9,10])
    l.add([7,8])
    l.add([4,5,6])
    print(l.result())