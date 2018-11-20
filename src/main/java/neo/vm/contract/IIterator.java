package neo.vm.contract;

import neo.vm.AbstractStackItem;
import neo.vm.IInteropInterface;

public interface IIterator extends IInteropInterface {
	void Dispose();

	AbstractStackItem Key();

	boolean Next();

	AbstractStackItem Value();
}

// using Neo.VM;
// using System;
//
// namespace Neo.SmartContract
// {
// internal abstract class IIterator : IDisposable, IInteropInterface
// {
// public abstract void Dispose();
// public abstract StackItem Key();
// public abstract bool Next();
// public abstract StackItem Value();
// }
// }
