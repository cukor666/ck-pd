package main

import (
	"fmt"
	"sync"
	"time"
)

// Locker 负责闲置自动锁定与剪贴板自动清除。
//
// 设计要点：
//   - 看门狗是独立 goroutine，不依赖前端的定时器；即使前端卡死或渲染层
//     行为异常，闲置锁定依然会生效。
//   - 剪贴板清除使用代数（generation）判定有效性，保证连续复制时只有
//     最后一次复制的定时器会真正清除剪贴板，不会误清更新的内容。
type Locker struct {
	mu        sync.Mutex
	interval  time.Duration
	clipDelay time.Duration

	stop      chan struct{}
	stopped   bool
	clipGen   uint64
	idleLimit time.Duration

	// 回调由 App 注入。
	onAutoLock func()
	onClipFire func(msg string)
}

// NewLocker 创建看门狗。
func NewLocker() *Locker {
	return &Locker{
		interval:  5 * time.Second,
		clipDelay: 30 * time.Second,
		stop:      make(chan struct{}),
	}
}

// Configure 更新自动锁定与剪贴板清除时长。idleMinutes 为 0 表示不自动锁定。
func (l *Locker) Configure(idleMinutes, clipSeconds int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idleMinutes > 0 {
		l.idleLimit = time.Duration(idleMinutes) * time.Minute
	} else {
		l.idleLimit = 0
	}
	if clipSeconds > 0 {
		l.clipDelay = time.Duration(clipSeconds) * time.Second
	} else {
		l.clipDelay = 30 * time.Second
	}
}

// Start 启动看门狗循环。
//
// idle 由调用方提供，返回保险库的闲置时长；不再解锁状态时应返回 0。
func (l *Locker) Start(idle func() time.Duration, onAutoLock func(), onClipFire func(msg string)) {
	l.mu.Lock()
	l.onAutoLock = onAutoLock
	l.onClipFire = onClipFire
	stop := l.stop
	l.mu.Unlock()

	go func() {
		ticker := time.NewTicker(l.interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				l.mu.Lock()
				limit := l.idleLimit
				cb := l.onAutoLock
				l.mu.Unlock()
				if limit <= 0 || cb == nil {
					continue
				}
				if d := idle(); d > 0 && d >= limit {
					cb()
				}
			}
		}
	}()
}

// Stop 停止看门狗，进程退出前调用。
func (l *Locker) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped {
		return
	}
	l.stopped = true
	close(l.stop)
}

// ScheduleClipboardClear 安排一次剪贴板清除。
// 若在延迟期间又发生新的复制，本次任务会自动作废。
func (l *Locker) ScheduleClipboardClear() uint64 {
	l.mu.Lock()
	l.clipGen++
	gen := l.clipGen
	delay := l.clipDelay
	cb := l.onClipFire
	l.mu.Unlock()

	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		<-timer.C

		l.mu.Lock()
		stale := gen != l.clipGen
		l.mu.Unlock()
		if stale {
			return
		}
		if cb != nil {
			cb(fmt.Sprintf("剪贴板中的密码已在 %s 后自动清除", HumanDuration(delay)))
		}
	}()
	return gen
}

// CancelClipboardClear 让当前待执行的清除任务作废（例如用户主动清空剪贴板）。
func (l *Locker) CancelClipboardClear() {
	l.mu.Lock()
	l.clipGen++
	l.mu.Unlock()
}

// HumanDuration 输出中文时长描述。
func HumanDuration(d time.Duration) string {
	secs := int(d.Seconds())
	switch {
	case secs < 60:
		return fmt.Sprintf("%d 秒", secs)
	case secs%60 == 0:
		return fmt.Sprintf("%d 分钟", secs/60)
	default:
		return fmt.Sprintf("%d 分 %d 秒", secs/60, secs%60)
	}
}
