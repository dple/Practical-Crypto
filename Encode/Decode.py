"""
Decode a given string. The encoding rule is: k[encoded_string], where the encoded_string inside the square brackets is being repeated exactly k times. 
Note that k is guaranteed to be a positive integer.

Input: s = "3[a]2[bc]"
Output: "aaabcbc"
"""
from queue import LifoQueue

class Solution:
    def deconding(self, s: str) -> str:
        res = ""
        stack_digits = LifoQueue()        
        stack_substrings = LifoQueue()
        curNum = 0
        
        for c in s:            
            if c.isdigit():
                curNum = curNum * 10 + int(c)

            elif c == '[':
                stack_digits.put(curNum)
                stack_substrings.put(res)
                res = ''
                curNum = 0

            elif c == ']':
                k = stack_digits.get()   
                prevString = stack_substrings.get()
                res = prevString + k * res             
                

            else:       # letters
                 res += c
                
        
        return res

if __name__ == '__main__':
    s = "3[a2[bd3[c]]]" # "100[leetcode]" #"3[a]2[bc]" #"2[abc]3[cd]ef" # "abc3[cd]xyz" #           

    sol = Solution()

    print(sol.deconding(s))