#include <string>
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <chrono>
#include <random>


const int numIterations = 500000;
int pregeneratedrandoms[numIterations];

void writeFile(const std::string & fileName, const std::string & data) {

	HANDLE hFile;
	DWORD dwBytesToWrite = (DWORD)data.length();
	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;

	hFile = CreateFileA(fileName.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		std::cout << "Terminal failure: Unable to open file for write.\n";
		return;
	}
	bErrorFlag = WriteFile(hFile, data.c_str(), dwBytesToWrite, &dwBytesWritten, NULL);

	if (FALSE == bErrorFlag) {
		std::cout << "Terminal failure: Unable to write to file.\n";
	}
	else {
		if (dwBytesWritten != dwBytesToWrite) {
			// This is an error because a synchronous write that results in success (WriteFile returns TRUE) should write all data as
			// requested. This would not necessarily be the case for asynchronous writes.
			printf("Error: dwBytesWritten != dwBytesToWrite\n");
		}
	}
	CloseHandle(hFile);
}

void calculateAvarageWriteTimeToDifferentFile(int iteration, const std::string& data) {
	std::cout << "Write Different File. Size: " << data.size() << " Iteration : " << iteration << std::endl;
	auto t1 = std::chrono::high_resolution_clock::now();
	for (auto i = iteration; i--; ) {
		writeFile(std::to_string(pregeneratedrandoms[i]), data);
	}
	auto t2 = std::chrono::high_resolution_clock::now();
	std::cout << " Avarage Time :  "<< (std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()) / (double)iteration
		<< " microsecond\n";
}

void test1KB() {
	std::string _1KB(1024, 'a');
	calculateAvarageWriteTimeToDifferentFile(numIterations, _1KB);
}

void test32KB() {
	std::string _32KB(32 * 1024, 'a');
	calculateAvarageWriteTimeToDifferentFile(numIterations, _32KB);
}

void test256KB() {
	std::string _256KB(256 * 1024, 'a');
	calculateAvarageWriteTimeToDifferentFile(numIterations, _256KB);
}

void test1MB() {
	std::string _1MB(1024 * 1024, 'a');
	calculateAvarageWriteTimeToDifferentFile(numIterations, _1MB);
}
void test4MB() {
	std::string _4MB(1024 * 1024 * 4, 'a');
	calculateAvarageWriteTimeToDifferentFile(numIterations, _4MB);
}


int main(int argc, char ** argv) {

	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(0); //Standard mersenne_twister_engine seeded with -- constant 0 instead rd()
	std::uniform_int_distribution<> dis(1, 100);
	for (int i = 0; i < numIterations; ++i)
		pregeneratedrandoms[i] = dis(gen);


	std::cin.get();
	std::string _1KB(1024, 'a');
	calculateAvarageWriteTimeToDifferentFile(numIterations, _1KB); 


	std::cout << "Test2 : 1KB - 32KB - 256KB - 1MB - 4Mb" << std::endl;
	test1KB();
	test32KB();
	test256KB();
	test1MB();
	test4MB();
	std::cout << "--------------------------------------" << std::endl;

	std::cin.get();
	return 0;
}

