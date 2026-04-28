CXX = g++
CXXFLAGS = -std=c++17 -Wall

SRCS = url_decode.cpp base32_decode.cpp sha.cpp TOTP.cpp example/main.cpp    
OBJS = $(SRCS:.cpp=.o)

example/totp: $(OBJS)
	$(CXX) $(CXXFLAGS) -o example/totp $(OBJS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) example/totp
