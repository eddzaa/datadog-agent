// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package ptracer holds the start command of CWS injector
package ptracer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/DataDog/datadog-agent/pkg/security/proto/ebpfless"
)

func registerFIMHandlers(handlers map[int]syscallHandler) ([]string, []string) {
	fimHandlers := []syscallHandler{
		{
			IDs:        []syscallID{{ID: OpenNr, Name: "open"}},
			Func:       handleOpen,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleOpensRet,
		},
		{
			IDs:        []syscallID{{ID: OpenatNr, Name: "openat"}},
			Func:       handleOpenAt,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleOpensRet,
		},
		{
			IDs:        []syscallID{{ID: Openat2Nr, Name: "openat2"}},
			Func:       handleOpenAt2,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleOpensRet,
		},
		{
			IDs:        []syscallID{{ID: CreatNr, Name: "creat"}},
			Func:       handleCreat,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleOpensRet,
		},
		{
			IDs:        []syscallID{{ID: NameToHandleAtNr, Name: "name_to_handle_at"}},
			Func:       handleNameToHandleAt,
			ShouldSend: nil,
			RetFunc:    handleNameToHandleAtRet,
		},
		{
			IDs:        []syscallID{{ID: OpenByHandleAtNr, Name: "open_by_handle_at"}},
			Func:       handleOpenByHandleAt,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleOpensRet,
		},
		{
			IDs:        []syscallID{{ID: MemfdCreateNr, Name: "memfd_create"}},
			Func:       handleMemfdCreate,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleOpensRet,
		},
		{
			IDs:        []syscallID{{ID: FcntlNr, Name: "fcntl"}},
			Func:       handleFcntl,
			ShouldSend: nil,
			RetFunc:    handleFcntlRet,
		},
		{
			IDs:        []syscallID{{ID: DupNr, Name: "dup"}, {ID: Dup2Nr, Name: "dup2"}, {ID: Dup3Nr, Name: "dup3"}},
			Func:       handleDup,
			ShouldSend: nil,
			RetFunc:    handleDupRet,
		},
		{
			IDs:        []syscallID{{ID: CloseNr, Name: "close"}},
			Func:       handleClose,
			ShouldSend: nil,
			RetFunc:    nil,
		},
		{
			IDs:        []syscallID{{ID: UnlinkNr, Name: "unlink"}},
			Func:       handleUnlink,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
		{
			IDs:        []syscallID{{ID: UnlinkatNr, Name: "unlinkat"}},
			Func:       handleUnlinkat,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
		{
			IDs:        []syscallID{{ID: RmdirNr, Name: "rmdir"}},
			Func:       handleRmdir,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
		{
			IDs:        []syscallID{{ID: RenameNr, Name: "rename"}},
			Func:       handleRename,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleRenamesRet,
		},
		{
			IDs:        []syscallID{{ID: RenameAtNr, Name: "renameat"}, {ID: RenameAt2Nr, Name: "renameat2"}},
			Func:       handleRenameAt,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleRenamesRet,
		},
		{
			IDs:        []syscallID{{ID: MkdirNr, Name: "mkdir"}},
			Func:       handleMkdir,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleMkdirRet,
		},
		{
			IDs:        []syscallID{{ID: MkdirAtNr, Name: "mkdirat"}},
			Func:       handleMkdirAt,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleMkdirRet,
		},
		{
			IDs:        []syscallID{{ID: UtimeNr, Name: "utime"}},
			Func:       handleUtime,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
		{
			IDs:        []syscallID{{ID: UtimesNr, Name: "utimes"}},
			Func:       handleUtimes,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
		{
			IDs:        []syscallID{{ID: UtimensAtNr, Name: "utimensat"}, {ID: FutimesAtNr, Name: "futimesat"}},
			Func:       handleUtimensAt,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
		{
			IDs:        []syscallID{{ID: LinkNr, Name: "link"}},
			Func:       handleLink,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleLinksRet,
		},
		{
			IDs:        []syscallID{{ID: LinkAtNr, Name: "linkat"}},
			Func:       handleLinkAt,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleLinksRet,
		},
		{
			IDs:        []syscallID{{ID: SymlinkNr, Name: "symlink"}},
			Func:       handleSymlink,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleLinksRet,
		},
		{
			IDs:        []syscallID{{ID: SymlinkAtNr, Name: "symlinkat"}},
			Func:       handleSymlinkAt,
			ShouldSend: isAcceptedRetval,
			RetFunc:    handleLinksRet,
		},
		{
			IDs:        []syscallID{{ID: ChmodNr, Name: "chmod"}},
			Func:       handleChmod,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
		{
			IDs:        []syscallID{{ID: FchmodNr, Name: "fchmod"}},
			Func:       handleFchmod,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
		{
			// IDs:        []syscallID{{ID: FchmodAtNr, Name: "fchmodat"}, {ID: FchmodAt2Nr, Name: "fchmodat2"}},
			IDs:        []syscallID{{ID: FchmodAtNr, Name: "fchmodat"}},
			Func:       handleFchmodAt,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},

		{
			IDs: []syscallID{
				{ID: ChownNr, Name: "chown"},
				{ID: LchownNr, Name: "lchown"},
				// {ID: ChownNr | 0x40000000, Name: "chown", SyscallABI: syscallABI32Bits},
				{ID: 182 /* 1073741916 */ /* 92 | 0x40000000 */, Name: "chown", SyscallABI: syscallABI32Bits},
				{ID: 95 /* 1073741916 */ /* 92 | 0x40000000 */, Name: "fchown", SyscallABI: syscallABI32Bits},
			},
			// IDs:        []syscallID{{ID: ChownNr, Name: "chown"}, {ID: LchownNr, Name: "lchown"}},
			Func:       handleChown,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
		{
			IDs:        []syscallID{{ID: FchownNr, Name: "fchown"}},
			Func:       handleFchown,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
		{
			IDs:        []syscallID{{ID: FchownAtNr, Name: "fchownat"}},
			Func:       handleFchownAt,
			ShouldSend: isAcceptedRetval,
			RetFunc:    nil,
		},
	}

	syscallList32 := []string{}
	syscallList64 := []string{}
	for _, h := range fimHandlers {
		for _, id := range h.IDs {
			if id.ID >= 0 { // insert only available syscalls
				handlers[id.ID] = h
				if id.SyscallABI == syscallABI32Bits {
					syscallList32 = append(syscallList32, id.Name)
				} else {
					syscallList64 = append(syscallList64, id.Name)
				}
			}
		}
	}
	return syscallList32, syscallList64
}

//
// handlers called on syscall entrance
//

func handleOpenAt(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFd(process, filename, fd)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeOpen
	msg.Open = &ebpfless.OpenSyscallMsg{
		Filename: filename,
		Flags:    uint32(tracer.ReadArgUint64(regs, 2)),
		Mode:     uint32(tracer.ReadArgUint64(regs, 3)),
	}

	return fillFileMetadata(filename, msg.Open, disableStats)
}

func handleOpenAt2(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFd(process, filename, fd)
	if err != nil {
		return err
	}

	howData, err := tracer.ReadArgData(process.Pid, regs, 2, 16 /*sizeof uint64 + sizeof uint64*/) // flags, mode
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeOpen
	msg.Open = &ebpfless.OpenSyscallMsg{
		Filename: filename,
		Flags:    uint32(binary.NativeEndian.Uint64(howData[:8])),
		Mode:     uint32(binary.NativeEndian.Uint64(howData[8:16])),
	}

	return fillFileMetadata(filename, msg.Open, disableStats)
}

func handleOpen(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFilename(process, filename)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeOpen
	msg.Open = &ebpfless.OpenSyscallMsg{
		Filename: filename,
		Flags:    uint32(tracer.ReadArgUint64(regs, 1)),
		Mode:     uint32(tracer.ReadArgUint64(regs, 2)),
	}

	return fillFileMetadata(filename, msg.Open, disableStats)
}

func handleCreat(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFilename(process, filename)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeOpen
	msg.Open = &ebpfless.OpenSyscallMsg{
		Filename: filename,
		Flags:    unix.O_CREAT | unix.O_WRONLY | unix.O_TRUNC,
		Mode:     uint32(tracer.ReadArgUint64(regs, 1)),
	}

	return fillFileMetadata(filename, msg.Open, disableStats)
}

func handleMemfdCreate(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}
	filename = "memfd:" + filename

	msg.Type = ebpfless.SyscallTypeOpen
	msg.Open = &ebpfless.OpenSyscallMsg{
		Filename: filename,
		Flags:    uint32(tracer.ReadArgUint64(regs, 1)),
	}
	return nil
}

func handleNameToHandleAt(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFd(process, filename, fd)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeOpen
	msg.Open = &ebpfless.OpenSyscallMsg{
		Filename: filename,
	}
	return nil
}

func handleOpenByHandleAt(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	pFileHandleData, err := tracer.ReadArgData(process.Pid, regs, 1, 8 /*sizeof uint32 + sizeof int32*/)
	if err != nil {
		return err
	}

	key := fileHandleKey{
		handleBytes: binary.BigEndian.Uint32(pFileHandleData[:4]),
		handleType:  int32(binary.BigEndian.Uint32(pFileHandleData[4:8])),
	}
	val, ok := process.Res.FileHandleCache[key]
	if !ok {
		return errors.New("didn't find correspondance in the file handle cache")
	}
	msg.Type = ebpfless.SyscallTypeOpen
	msg.Open = &ebpfless.OpenSyscallMsg{
		Filename: val.pathName,
		Flags:    uint32(tracer.ReadArgUint64(regs, 2)),
	}
	return fillFileMetadata(val.pathName, msg.Open, disableStats)
}

func handleUnlinkat(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	flags := tracer.ReadArgInt32(regs, 2)

	filename, err = getFullPathFromFd(process, filename, fd)
	if err != nil {
		return err
	}

	if flags == unix.AT_REMOVEDIR {
		msg.Type = ebpfless.SyscallTypeRmdir
		msg.Rmdir = &ebpfless.RmdirSyscallMsg{
			File: ebpfless.OpenSyscallMsg{
				Filename: filename,
			},
		}
		err = fillFileMetadata(filename, &msg.Rmdir.File, disableStats)
	} else {
		msg.Type = ebpfless.SyscallTypeUnlink
		msg.Unlink = &ebpfless.UnlinkSyscallMsg{
			File: ebpfless.OpenSyscallMsg{
				Filename: filename,
			},
		}
		err = fillFileMetadata(filename, &msg.Unlink.File, disableStats)
	}
	return err
}

func handleUnlink(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFilename(process, filename)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeUnlink
	msg.Unlink = &ebpfless.UnlinkSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
	}
	return fillFileMetadata(filename, &msg.Unlink.File, disableStats)
}

func handleRmdir(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFilename(process, filename)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeRmdir
	msg.Rmdir = &ebpfless.RmdirSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
	}
	return fillFileMetadata(filename, &msg.Rmdir.File, disableStats)
}

func handleRename(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	oldFilename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	oldFilename, err = getFullPathFromFilename(process, oldFilename)
	if err != nil {
		return err
	}

	newFilename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	newFilename, err = getFullPathFromFilename(process, newFilename)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeRename
	msg.Rename = &ebpfless.RenameSyscallMsg{
		OldFile: ebpfless.OpenSyscallMsg{
			Filename: oldFilename,
		},
		NewFile: ebpfless.OpenSyscallMsg{
			Filename: newFilename,
		},
	}
	return fillFileMetadata(oldFilename, &msg.Rename.OldFile, disableStats)
}

func handleRenameAt(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	oldFD := tracer.ReadArgInt32(regs, 0)

	oldFilename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	oldFilename, err = getFullPathFromFd(process, oldFilename, oldFD)
	if err != nil {
		return err
	}

	newFD := tracer.ReadArgInt32(regs, 2)

	newFilename, err := tracer.ReadArgString(process.Pid, regs, 3)
	if err != nil {
		return err
	}

	newFilename, err = getFullPathFromFd(process, newFilename, newFD)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeRename
	msg.Rename = &ebpfless.RenameSyscallMsg{
		OldFile: ebpfless.OpenSyscallMsg{
			Filename: oldFilename,
		},
		NewFile: ebpfless.OpenSyscallMsg{
			Filename: newFilename,
		},
	}
	return fillFileMetadata(oldFilename, &msg.Rename.OldFile, disableStats)
}

func handleFcntl(tracer *Tracer, _ *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	msg.Fcntl = &ebpfless.FcntlSyscallMsg{
		Fd:  tracer.ReadArgUint32(regs, 0),
		Cmd: tracer.ReadArgUint32(regs, 1),
	}
	return nil
}

func handleDup(tracer *Tracer, _ *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	// using msg to temporary store arg0, as it will be erased by the return value on ARM64
	msg.Dup = &ebpfless.DupSyscallFakeMsg{
		OldFd: tracer.ReadArgInt32(regs, 0),
	}
	return nil
}

func handleClose(tracer *Tracer, process *Process, _ *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	fd := tracer.ReadArgInt32(regs, 0)
	delete(process.Res.Fd, fd)
	return nil
}

func handleMkdirAt(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFd(process, filename, fd)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeMkdir
	msg.Mkdir = &ebpfless.MkdirSyscallMsg{
		Dir: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		Mode: uint32(tracer.ReadArgUint64(regs, 2)),
	}
	return nil
}

func handleMkdir(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFilename(process, filename)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeMkdir
	msg.Mkdir = &ebpfless.MkdirSyscallMsg{
		Dir: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		Mode: uint32(tracer.ReadArgUint64(regs, 1)),
	}
	return nil
}

func handleUtime(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFilename(process, filename)
	if err != nil {
		return err
	}

	var atime, mtime uint64
	pTimes := tracer.ReadArgUint64(regs, 1)
	// first, check the given pointer. if null, apply current time
	if pTimes == 0 {
		atime = uint64(time.Now().UnixNano())
		mtime = atime
	} else {
		times, err := tracer.ReadArgData(process.Pid, regs, 1, 16 /*sizeof uint64 *2*/) // ATime,CTime
		if err != nil {
			return err
		}
		atime = secsToNanosecs(binary.NativeEndian.Uint64(times[:8]))
		mtime = secsToNanosecs(binary.NativeEndian.Uint64(times[8:16]))
	}

	msg.Type = ebpfless.SyscallTypeUtimes
	msg.Utimes = &ebpfless.UtimesSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		ATime: atime,
		MTime: mtime,
	}
	return fillFileMetadata(msg.Utimes.File.Filename, &msg.Utimes.File, disableStats)
}

func handleUtimes(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFilename(process, filename)
	if err != nil {
		return err
	}

	var atime, mtime uint64
	pTimes := tracer.ReadArgUint64(regs, 1)
	// first, check the given pointer. if null, apply current time
	if pTimes == 0 {
		atime = uint64(time.Now().UnixNano())
		mtime = atime
	} else {
		times, err := tracer.ReadArgData(process.Pid, regs, 1, 32 /*sizeof uint64 *4*/) // ATime,CTime
		if err != nil {
			return err
		}
		atime = secsToNanosecs(binary.NativeEndian.Uint64(times[:8]))
		atime += microsecsToNanosecs(binary.NativeEndian.Uint64(times[8:16]))
		mtime = secsToNanosecs(binary.NativeEndian.Uint64(times[16:24]))
		mtime += microsecsToNanosecs(binary.NativeEndian.Uint64(times[24:32]))
	}

	msg.Type = ebpfless.SyscallTypeUtimes
	msg.Utimes = &ebpfless.UtimesSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		ATime: atime,
		MTime: mtime,
	}
	return fillFileMetadata(msg.Utimes.File.Filename, &msg.Utimes.File, disableStats)
}

func handleUtimensAt(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFd(process, filename, fd)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFilename(process, filename)
	if err != nil {
		return err
	}

	var now uint64
	getCurrentTimestamp := func() uint64 {
		if now == 0 {
			now = uint64(time.Now().UnixNano())
		}
		return now
	}

	var atime, mtime uint64
	pTimes := tracer.ReadArgUint64(regs, 2)
	// first, check the given pointer. if null, apply current time
	if pTimes == 0 {
		atime = getCurrentTimestamp()
		mtime = getCurrentTimestamp()
	} else {
		times, err := tracer.ReadArgData(process.Pid, regs, 2, 32 /*sizeof uint64 *4*/) // ATime,CTime
		if err != nil {
			return err
		}
		atime = secsToNanosecs(binary.NativeEndian.Uint64(times[:8]))
		if atime == unix.UTIME_NOW {
			atime = getCurrentTimestamp()
		} else {
			nsecs := binary.NativeEndian.Uint64(times[8:16])
			if nsecs == unix.UTIME_OMIT {
				atime = 0
			} else {
				atime += nsecs
			}
		}
		mtime = secsToNanosecs(binary.NativeEndian.Uint64(times[16:24]))
		if mtime == unix.UTIME_NOW {
			mtime = getCurrentTimestamp()
		} else {
			nsecs := binary.NativeEndian.Uint64(times[24:32])
			if nsecs == unix.UTIME_OMIT {
				mtime = 0
			} else {
				mtime += nsecs
			}
		}
	}

	msg.Type = ebpfless.SyscallTypeUtimes
	msg.Utimes = &ebpfless.UtimesSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		ATime: atime,
		MTime: mtime,
	}
	return fillFileMetadata(msg.Utimes.File.Filename, &msg.Utimes.File, disableStats)
}

func handleLink(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	targetFilename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	targetFilename, err = getFullPathFromFilename(process, targetFilename)
	if err != nil {
		return err
	}

	linkFilename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	linkFilename, err = getFullPathFromFilename(process, linkFilename)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeLink
	msg.Link = &ebpfless.LinkSyscallMsg{
		Type: ebpfless.LinkTypeHardlink,
		Target: ebpfless.OpenSyscallMsg{
			Filename: targetFilename,
		},
		Link: ebpfless.OpenSyscallMsg{
			Filename: linkFilename,
		},
	}
	return fillFileMetadata(targetFilename, &msg.Link.Target, disableStats)
}

func handleLinkAt(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	targetFD := tracer.ReadArgInt32(regs, 0)

	targetFilename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	targetFilename, err = getFullPathFromFd(process, targetFilename, targetFD)
	if err != nil {
		return err
	}

	linkFD := tracer.ReadArgInt32(regs, 2)

	linkFilename, err := tracer.ReadArgString(process.Pid, regs, 3)
	if err != nil {
		return err
	}

	linkFilename, err = getFullPathFromFd(process, linkFilename, linkFD)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeLink
	msg.Link = &ebpfless.LinkSyscallMsg{
		Type: ebpfless.LinkTypeHardlink,
		Target: ebpfless.OpenSyscallMsg{
			Filename: targetFilename,
		},
		Link: ebpfless.OpenSyscallMsg{
			Filename: linkFilename,
		},
	}
	return fillFileMetadata(targetFilename, &msg.Link.Target, disableStats)
}

func handleSymlink(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	targetFilename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}

	targetFilename, err = getFullPathFromFilename(process, targetFilename)
	if err != nil {
		return err
	}

	linkFilename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	linkFilename, err = getFullPathFromFilename(process, linkFilename)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeLink
	msg.Link = &ebpfless.LinkSyscallMsg{
		Type: ebpfless.LinkTypeSymbolic,
		Target: ebpfless.OpenSyscallMsg{
			Filename: targetFilename,
		},
		Link: ebpfless.OpenSyscallMsg{
			Filename: linkFilename,
		},
	}
	return fillFileMetadata(targetFilename, &msg.Link.Target, disableStats)
}

func handleSymlinkAt(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	targetFD := tracer.ReadArgInt32(regs, 0)

	targetFilename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	targetFilename, err = getFullPathFromFd(process, targetFilename, targetFD)
	if err != nil {
		return err
	}

	linkFD := tracer.ReadArgInt32(regs, 2)

	linkFilename, err := tracer.ReadArgString(process.Pid, regs, 3)
	if err != nil {
		return err
	}

	linkFilename, err = getFullPathFromFd(process, linkFilename, linkFD)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeLink
	msg.Link = &ebpfless.LinkSyscallMsg{
		Type: ebpfless.LinkTypeSymbolic,
		Target: ebpfless.OpenSyscallMsg{
			Filename: targetFilename,
		},
		Link: ebpfless.OpenSyscallMsg{
			Filename: linkFilename,
		},
	}
	return fillFileMetadata(targetFilename, &msg.Link.Target, disableStats)
}

func handleChmod(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	if err != nil {
		return err
	}
	filename, err = getFullPathFromFilename(process, filename)
	if err != nil {
		return err
	}
	msg.Type = ebpfless.SyscallTypeChmod
	msg.Chmod = &ebpfless.ChmodSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		Mode: uint32(tracer.ReadArgUint64(regs, 1)),
	}
	return fillFileMetadata(filename, &msg.Chmod.File, disableStats)
}

func handleFchmod(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, found := process.Res.Fd[fd]
	if !found {
		return errors.New("FD cache incomplete")
	}

	msg.Type = ebpfless.SyscallTypeChmod
	msg.Chmod = &ebpfless.ChmodSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		Mode: uint32(tracer.ReadArgUint64(regs, 1)),
	}
	return fillFileMetadata(filename, &msg.Chmod.File, disableStats)
}

func handleFchmodAt(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFd(process, filename, fd)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeChmod
	msg.Chmod = &ebpfless.ChmodSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		Mode: uint32(tracer.ReadArgUint64(regs, 2)),
	}
	return fillFileMetadata(filename, &msg.Chmod.File, disableStats)
}

func handleChown(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {

	dumpRegs(regs)

	// ARG0
	arg0, err := tracer.readString32(process.Pid, uint32(regs.R15))
	if err != nil {
		return err
	}
	// ARG1
	arg1 := uint32(regs.R15 >> 32)
	// ARG2
	arg2 := uint32(regs.R14)
	fmt.Printf("ARG0: %s, ARG1: %d, ARG2: %d\n", arg0, arg1, arg2)

	// filename, err := tracer.ReadArgString(process.Pid, regs, 0)
	filename, err := tracer.ReadArgString(process.Pid, regs, 3)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFilename(process, filename)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeChown
	msg.Chown = &ebpfless.ChownSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		UID: int32(tracer.ReadArgUint64(regs, 1)),
		GID: int32(tracer.ReadArgUint64(regs, 2)),
	}
	return fillFileMetadata(filename, &msg.Chown.File, disableStats)
}

func handleFchown(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, found := process.Res.Fd[fd]
	if !found {
		return errors.New("FD cache incomplete")
	}

	msg.Type = ebpfless.SyscallTypeChown
	msg.Chown = &ebpfless.ChownSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		UID: int32(tracer.ReadArgUint64(regs, 1)),
		GID: int32(tracer.ReadArgUint64(regs, 2)),
	}
	return fillFileMetadata(filename, &msg.Chown.File, disableStats)
}

func handleFchownAt(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	fd := tracer.ReadArgInt32(regs, 0)

	filename, err := tracer.ReadArgString(process.Pid, regs, 1)
	if err != nil {
		return err
	}

	filename, err = getFullPathFromFd(process, filename, fd)
	if err != nil {
		return err
	}

	msg.Type = ebpfless.SyscallTypeChown
	msg.Chown = &ebpfless.ChownSyscallMsg{
		File: ebpfless.OpenSyscallMsg{
			Filename: filename,
		},
		UID: int32(tracer.ReadArgUint64(regs, 2)),
		GID: int32(tracer.ReadArgUint64(regs, 3)),
	}
	return fillFileMetadata(filename, &msg.Chown.File, disableStats)
}

//
// handlers called on syscall return
//

func handleNameToHandleAtRet(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	if msg.Open == nil {
		return errors.New("msg empty")
	}

	if ret := tracer.ReadRet(regs); ret < 0 {
		return errors.New("syscall failed")
	}

	pFileHandleData, err := tracer.ReadArgData(process.Pid, regs, 2, 8 /*sizeof uint32 + sizeof int32*/)
	if err != nil {
		return err
	}

	key := fileHandleKey{
		handleBytes: binary.BigEndian.Uint32(pFileHandleData[:4]),
		handleType:  int32(binary.BigEndian.Uint32(pFileHandleData[4:8])),
	}
	process.Res.FileHandleCache[key] = &fileHandleVal{
		pathName: msg.Open.Filename,
	}
	return nil
}

func handleOpensRet(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	if ret := tracer.ReadRet(regs); msg.Open != nil && ret > 0 {
		process.Res.Fd[int32(ret)] = msg.Open.Filename
	}
	return nil
}

func handleFcntlRet(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	if ret := tracer.ReadRet(regs); msg.Fcntl != nil && ret >= 0 {
		// maintain fd/path mapping
		if msg.Fcntl.Cmd == unix.F_DUPFD || msg.Fcntl.Cmd == unix.F_DUPFD_CLOEXEC {
			if path, exists := process.Res.Fd[int32(msg.Fcntl.Fd)]; exists {
				process.Res.Fd[int32(ret)] = path
			}
		}
	}
	return nil
}

func handleDupRet(tracer *Tracer, process *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, _ bool) error {
	if ret := tracer.ReadRet(regs); msg.Dup != nil && ret >= 0 {
		if path, ok := process.Res.Fd[msg.Dup.OldFd]; ok {
			// maintain fd/path in case of dups
			process.Res.Fd[int32(ret)] = path
		}
	}
	return nil
}

func handleRenamesRet(tracer *Tracer, _ *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	if ret := tracer.ReadRet(regs); msg.Rename != nil && ret == 0 {
		return fillFileMetadata(msg.Rename.NewFile.Filename, &msg.Rename.NewFile, disableStats)
	}
	return nil
}

func handleMkdirRet(tracer *Tracer, _ *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	if ret := tracer.ReadRet(regs); msg.Mkdir != nil && ret == 0 {
		return fillFileMetadata(msg.Mkdir.Dir.Filename, &msg.Mkdir.Dir, disableStats)
	}
	return nil
}

func handleLinksRet(tracer *Tracer, _ *Process, msg *ebpfless.SyscallMsg, regs syscall.PtraceRegs, disableStats bool) error {
	if ret := tracer.ReadRet(regs); msg.Link != nil && ret == 0 {
		return fillFileMetadata(msg.Link.Link.Filename, &msg.Link.Link, disableStats)
	}
	return nil
}
