// #target: macos-x64
module test;
import std::io, std::time, std::math, std::collections;

List{long} stones;

struct Foo
{
	int[3] x;
}

fn int Foo.get(self, usz i) @operator([]) => self.x[i];
fn void Foo.set(&self, usz i, int z) @operator([]=) => self.x[i] = z;

fn void main() {
  stones.push(1);
  stones.push(100);
  stones[0] *= 3;
  stones[1] *= 2;
  stones[0] += 31;
  Foo z;
  z[$reflect(1)] += 5;
  z[1] *= 3;
}