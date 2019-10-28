import subprocess

s = subprocess.check_output(["./a.out", "test1.txt", "wordlist.txt"])
print(s)