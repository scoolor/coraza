// Copyright 2022 The Coraza Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package multipart

import (
	"mime/multipart"
	"net/textproto"
	"testing"
)

func TestOriginalFileName(t *testing.T) {
	tests := map[string][2]string{
		"no filename":       {` form-data ; name=foo`, ""},
		"contains filename": {`form-data; name="file"; filename="test.txt"`, "test.txt"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := &multipart.Part{
				Header: textproto.MIMEHeader{
					"Content-Disposition": []string{test[0]},
				},
			}
			if got, want := OriginFileName(p), test[1]; got != want {
				t.Errorf("OriginFileName(%v) = %v, want %v", p, got, want)
			}
		})
	}
}
