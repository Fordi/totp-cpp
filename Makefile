CXX = g++
CXXFLAGS = -std=c++17 -Wall

SRCS = url_decode.cpp base32_decode.cpp sha.cpp TOTP.cpp    
OBJS = $(SRCS:.cpp=.o)

example/totp: $(OBJS) example/main.o
	$(CXX) $(CXXFLAGS) -o example/totp $(OBJS) example/main.o

example/%.o: example/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

totp.js: $(SRCS)
	emcc $(CXXFLAGS) --bind -o $@ -sEXPORT_ES6 -sMODULARIZE $(SRCS)

clean:
	rm -f $(OBJS) example/totp *.js *.mjs *.wasm
