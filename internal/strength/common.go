package strength

import "strings"

// commonPasswords 是精选的高频弱密码集合（大小写不敏感匹配）。
// 这里控制在数百条以内：命中率最高的部分已覆盖绝大多数自动化
// 撞库尝试，同时避免引入数 MB 的字典文件。
var commonPasswords = map[string]struct{}{}

func init() {
	list := []string{
		"123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
		"111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
		"monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
		"mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
		"7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
		"jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
		"harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
		"charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
		"klaster", "112233", "george", "computer", "michelle", "jessica", "pepper",
		"1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
		"pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua",
		"cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea",
		"biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin",
		"thunder", "taylor", "matrix", "mobilemail", "mom", "monitor", "monitoring",
		"montana", "moon", "moscow", "admin", "administrator", "root", "toor",
		"guest", "test", "test123", "changeme", "welcome", "login", "user",
		"default", "secret", "letmein123", "p@ssw0rd", "passw0rd", "password1",
		"password123", "qwerty123", "1q2w3e4r", "1q2w3e", "zaq12wsx", "abcd1234",
		"a1b2c3", "abc12345", "123abc", "666888", "888888", "5201314", "woaini",
		"woaini1314", "qq123456", "123456789a", "a123456789", "asdasd", "asdfasdf",
		"qweqwe", "1111111111", "0000000000", "12121212", "12341234", "11223344",
		"china", "beijing", "shanghai", "shenzhen", "guangzhou", "xiaoming",
		"zhangwei", "wangwei", "liwei", "lihua", "liuwei", "chenjie", "yangyang",
		"football1", "basketball", "pussy", "dick", "fuck", "fuckyou", "asshole",
		"hitler", "sex", "sexy", "hotdog", "blahblah", "whatever", "nothing",
		"unknown", "qwertyui", "poiuytrewq", "lkjhgfdsa", "mnbvcxz", "0987654321",
		"741852963", "963852741", "147258369", "159357", "456789", "789456",
		"102030", "123654", "112211", "loveyou", "lovely", "iloveu", "forever",
		"hello", "helloworld", "internet", "service", "system", "manager",
		"network", "office", "school", "student", "teacher", "company",
		"apple", "google", "amazon", "facebook", "twitter", "linkedin",
		"wechat", "tencent", "baidu", "alibaba", "taobao", "jingdong",
		"windows", "linux", "ubuntu", "android", "iphone", "samsung",
		"gaming", "gamer", "player", "winner", "champion", "legend",
		"monkey123", "sunshine1", "princess1", "iloveyou1", "password12",
		"abc123456", "123456abc", "a123456", "abcabc", "aaa111", "qqqqqq",
		"zzzzzz", "xxxxxx", "cccccc", "vvvvvv", "bbbbbb", "nnnnnn",
		"asdfghjkl", "qwertyuiop123", "1qazxsw2", "2wsx3edc", "q1w2e3r4",
		"p@ssword", "pa55word", "passwd", "pass1234", "mypassword", "newpassword",
		"temppassword", "guest123", "admin123", "root123", "oracle", "postgres",
		"mysql", "sqlserver", "sa123456", "administrator123", "system123",
	}
	for _, p := range list {
		commonPasswords[strings.ToLower(p)] = struct{}{}
	}
}

// isCommon 判断是否为常见弱密码。
func isCommon(s string) bool {
	_, ok := commonPasswords[strings.ToLower(strings.TrimSpace(s))]
	return ok
}

// CommonCount 返回内置弱密码字典条目数，用于界面说明。
func CommonCount() int { return len(commonPasswords) }
