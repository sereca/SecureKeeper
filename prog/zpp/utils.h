/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors: Stefan Brenner, Colin Wulf
 */
/**
 * These functions should provide some basic functionalites like printing a byte array as hex
 * */
#ifndef _UTILS_H_
#define _UTILS_H_

//#define MAX_SIZE 81920

typedef struct {
	char * buffer;
	size_t size;
} package_t;

//typedef struct {
//	char buffer[MAX_SIZE];
//	size_t size;
//} fixed_package_t;

#ifdef __cplusplus
extern "C" {
#endif

void hexdump_p(package_t * p_package);
void hexdump(const char* desc, void* addr, int len);
void hexdump_clean(const char* desc, void* addr, int len);

#ifdef __cplusplus
}
#endif

#endif /* _UTILS_H_ */
