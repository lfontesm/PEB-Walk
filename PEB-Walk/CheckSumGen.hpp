#pragma once

#ifndef CHECKSUMGEN_
#define CHECKSUMGEN_

unsigned long check_sum_gen(const char* str) {
	unsigned long checksum = 1;
	for (size_t i = 0; str[i] != 0; i++){
		checksum *= str[i] + 0x12345678;
	}
	return checksum;
}

bool check_sum_is_eq(unsigned long sum1, unsigned long sum2) {
	return sum1 == sum2;
}

#endif // !CHECKSUMGEN_

