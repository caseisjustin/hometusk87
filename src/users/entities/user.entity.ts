import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  username: string;

  @Column()
  email: string;

  @Column()
  password: string;

  @Column({ default: false })
  isEmailConfirmed: boolean;

  @Column({nullable: true})
  emailVerificationToken: string;

  @Column({type: "timestamp", nullable: true})
  emailVerificationTokenExpires: Date
}
