import difflib
import json
import sys

def group_objects(json_file_path):
    with open(json_file_path, 'r') as f:
        data = json.load(f)

    grouped_objects = []
    temp = []

    for obj in data:
        if "command" in obj:
            if temp:
                grouped_objects.append(temp)
                temp = []
        temp.append(obj)

    if temp:
        grouped_objects.append(temp)

    return grouped_objects


def main():

	if len(sys.argv) != 3:
		print("Usage: diff.py <file1> <file2>")
		sys.exit(1)

	expected = group_objects(sys.argv[1])
	result = group_objects(sys.argv[2])

	# Verify that the list of commands is the same	
	cmdlist1 = []
	cmdlist2 = []
	for a in expected:
		cmdlist1.append(a[0]['command'].rstrip())
	for a in result:
		cmdlist2.append(a[0]['command'].rstrip())
	differ = difflib.Differ()
	diff = differ.compare(cmdlist1, cmdlist2)
	differences = [line for line in diff if line.startswith('-') or line.startswith('+')]
	if differences:
		print("Diff between what commands were run in the recorded result and the current testsuite:")
		for line in differences:
			print(line)
		sys.exit(1)

	# For each command, verify that the http calls and output is the same
	has_diff = False
	for i in range(len(expected)):
		cmd = expected[i][0]['command'].rstrip()
		cmd2 = result[i][0]['command'].rstrip()
		if cmd != cmd2:
			# This should never happen here, because it would get caught above
			print(f"Expected command: {cmd}\nActual command: {cmd2}")
			sys.exit(1)
		
		s1 = json.dumps(expected[i], indent=4).splitlines(keepends=True)
		s2 = json.dumps(result[i], indent=4).splitlines(keepends=True)
		if s1 != s2:
			has_diff = True
			print("=" * 72)
			print("Command:",cmd,"       -expected, +tested")
			print("=" * 72)
			gen = difflib.ndiff(s1,s2)
			sys.stdout.writelines(gen)
			print("\n") # 2 newlines

	if has_diff:
		sys.exit(1)

if __name__ == '__main__':
    main()
