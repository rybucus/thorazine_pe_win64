#include "src/defines.h"

int main( )
{
	import( kernel32.dll, Beep ).execute< BOOL >( 100, 500 );
}