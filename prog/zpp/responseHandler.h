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
#include "list.h"
#include "utils.h"

#ifndef _RESPONSE_HANDLER_H_
#define _RESPONSE_HANDLER_H_
/**
 * This function parses a response from zookeeper which is stored in 
 * input archive ia.
 * It analyzes it and decrypt it if necessary.
 * The output is stored in a output archive oa.
 * */
int handle_response(package_t * p_package, list_t * p_list);
#endif
