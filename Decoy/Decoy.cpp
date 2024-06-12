#include <iostream>
#include <Windows.h>

using namespace std;

// The main entry point of the program.
int main(int argc, char *argv[])
{
	// Enters the program loop
	while (TRUE)
	{
		// Checks if the process is being debugged.
		cout << "Being debugged: " << IsDebuggerPresent();
		// If a debugger is present.
		if (IsDebuggerPresent())
		{
			// Trigger an exception.
			cout << *(DWORD*)nullptr << endl;
		}
		// Waits for user.
		cin.get();
	}
	// Waits for user.
	// cin.get();
}